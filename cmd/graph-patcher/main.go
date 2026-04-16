// graph-patcher is a sidecar controller that reconciles Crossplane resources
// with Microsoft Graph API. It handles three responsibilities:
//
// 1. Catalog resolution: Watches AccessPackageBundle XRs, resolves
//    spec.catalogName → annotation identity.storebrand.no/catalog-id
//
// 2. Group membership: Reads spec.systemOwner UPNs from XRs, resolves them
//    to objectIds, and adds them as members of the approver group.
//
// 3. Custom schedule patching: Watches AccessPackageAssignmentPolicy resources
//    for the annotation azuread.upbound.io/allow-custom-schedule and patches
//    the corresponding Graph API object.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

const (
	annotationAllowCustomSchedule = "azuread.upbound.io/allow-custom-schedule"
	annotationLastPatched         = "azuread.upbound.io/graph-patcher-last-patched"
	annotationCatalogID           = "identity.storebrand.no/catalog-id"
	annotationMembersSync         = "identity.storebrand.no/members-synced"
)

var policyGVR = schema.GroupVersionResource{
	Group:    "accesspackages.azuread.upbound.io",
	Version:  "v1beta1",
	Resource: "accesspackageassignmentpolicies",
}

var xrGVR = schema.GroupVersionResource{
	Group:    "identity.storebrand.no",
	Version:  "v1alpha1",
	Resource: "accesspackagebundles",
}

type graphToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type graphClient struct {
	tenantID     string
	clientID     string
	clientSecret string
	token        string
	tokenExpiry  time.Time
}

func newGraphClient() (*graphClient, error) {
	tenantID := os.Getenv("ARM_TENANT_ID")
	clientID := os.Getenv("ARM_CLIENT_ID")
	clientSecret := os.Getenv("ARM_CLIENT_SECRET")
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("ARM_TENANT_ID, ARM_CLIENT_ID, ARM_CLIENT_SECRET must be set")
	}
	return &graphClient{
		tenantID:     tenantID,
		clientID:     clientID,
		clientSecret: clientSecret,
	}, nil
}

func (g *graphClient) getToken(ctx context.Context) (string, error) {
	if g.token != "" && time.Now().Before(g.tokenExpiry) {
		return g.token, nil
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", g.tenantID)
	data := url.Values{
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting token: %w", err)
	}
	defer resp.Body.Close()

	var tok graphToken
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("empty access token, status: %d", resp.StatusCode)
	}

	g.token = tok.AccessToken
	g.tokenExpiry = time.Now().Add(time.Duration(tok.ExpiresIn-60) * time.Second)
	return g.token, nil
}

// patchAssignmentPolicy sets allowCustomAssignmentSchedule on a Graph API
// assignment policy object. PUT is required (Graph doesn't support PATCH for
// this endpoint), so we GET first, modify, then PUT.
func (g *graphClient) patchAssignmentPolicy(ctx context.Context, policyID string, allowCustomSchedule bool) error {
	token, err := g.getToken(ctx)
	if err != nil {
		return err
	}

	// GET current policy
	getURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/assignmentPolicies/%s", policyID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return fmt.Errorf("creating GET request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET policy returned %d: %s", resp.StatusCode, string(body))
	}

	var policy map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		return fmt.Errorf("decoding policy: %w", err)
	}

	// Check if already set correctly
	if rs, ok := policy["requestorSettings"].(map[string]interface{}); ok {
		if current, ok := rs["allowCustomAssignmentSchedule"].(bool); ok && current == allowCustomSchedule {
			klog.V(2).Infof("policy %s: allowCustomAssignmentSchedule already %v, skipping", policyID, allowCustomSchedule)
			return nil
		}
	}

	// Modify only the target field in requestorSettings
	rs, ok := policy["requestorSettings"].(map[string]interface{})
	if !ok {
		rs = map[string]interface{}{}
	}
	rs["allowCustomAssignmentSchedule"] = allowCustomSchedule
	policy["requestorSettings"] = rs

	// Remove read-only / OData fields that Graph rejects on PUT
	delete(policy, "@odata.context")
	delete(policy, "id")
	delete(policy, "createdDateTime")
	delete(policy, "modifiedDateTime")
	delete(policy, "questions@odata.context")

	// PUT the full policy body so no fields get wiped
	bodyBytes, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshaling PUT body: %w", err)
	}

	putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, getURL, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("creating PUT request: %w", err)
	}
	putReq.Header.Set("Authorization", "Bearer "+token)
	putReq.Header.Set("Content-Type", "application/json")

	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		return fmt.Errorf("PUT policy: %w", err)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(putResp.Body)
		return fmt.Errorf("PUT policy returned %d: %s", putResp.StatusCode, string(body))
	}

	klog.Infof("policy %s: set allowCustomAssignmentSchedule=%v", policyID, allowCustomSchedule)
	return nil
}

// resolveCatalogName resolves an access package catalog display name to its ID.
func (g *graphClient) resolveCatalogName(ctx context.Context, catalogName string) (string, error) {
	token, err := g.getToken(ctx)
	if err != nil {
		return "", err
	}

	// List all catalogs and match by displayName client-side.
	// There are typically few catalogs, so filtering in-memory is fine.
	listURL := "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/catalogs?$select=id,displayName"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating catalog request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET catalogs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GET catalogs returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding catalogs: %w", err)
	}
	for _, cat := range result.Value {
		if strings.EqualFold(cat.DisplayName, catalogName) {
			return cat.ID, nil
		}
	}
	return "", fmt.Errorf("catalog %q not found", catalogName)
}

// resolveUPN resolves a user principal name to an objectId.
func (g *graphClient) resolveUPN(ctx context.Context, upn string) (string, error) {
	token, err := g.getToken(ctx)
	if err != nil {
		return "", err
	}

	userURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s?$select=id", url.PathEscape(upn))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GET user %s returned %d: %s", upn, resp.StatusCode, string(body))
	}

	var user struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", fmt.Errorf("decoding user: %w", err)
	}
	return user.ID, nil
}

// getGroupMembers returns the set of objectIds that are currently members of a group.
func (g *graphClient) getGroupMembers(ctx context.Context, groupID string) (map[string]bool, error) {
	token, err := g.getToken(ctx)
	if err != nil {
		return nil, err
	}

	membersURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/members?$select=id", groupID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, membersURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating members request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET members: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET members returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding members: %w", err)
	}

	members := make(map[string]bool, len(result.Value))
	for _, m := range result.Value {
		members[m.ID] = true
	}
	return members, nil
}

// addGroupMember adds a user as a member of a group.
func (g *graphClient) addGroupMember(ctx context.Context, groupID, userObjectID string) error {
	token, err := g.getToken(ctx)
	if err != nil {
		return err
	}

	addURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/members/$ref", groupID)
	body := fmt.Sprintf(`{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/%s"}`, userObjectID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addURL, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating add-member request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST add-member: %w", err)
	}
	defer resp.Body.Close()

	// 204 = added, 400 with "already exist" = already a member (idempotent)
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(string(respBody), "already exist") {
		return nil
	}
	return fmt.Errorf("POST add-member returned %d: %s", resp.StatusCode, string(respBody))
}

func getKubeClient() (dynamic.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig for local development
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = os.Getenv("HOME") + "/.kube/config"
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("building kube config: %w", err)
		}
	}
	return dynamic.NewForConfig(config)
}

func reconcile(ctx context.Context, client dynamic.Interface, graph *graphClient, obj *unstructured.Unstructured, forceVerify bool) {
	name := obj.GetName()
	annotations := obj.GetAnnotations()

	// Check for our annotation
	val, exists := annotations[annotationAllowCustomSchedule]
	if !exists {
		return
	}

	allowCustomSchedule := val != "false" // default true unless explicitly "false"

	// Get the policy ID from status.atProvider.id
	id, found, err := unstructured.NestedString(obj.Object, "status", "atProvider", "id")
	if err != nil || !found || id == "" {
		klog.V(2).Infof("policy %s: no atProvider.id yet, skipping", name)
		return
	}

	// On watch events, check annotation fingerprint to avoid redundant patches.
	// On periodic re-sync (forceVerify), skip the fingerprint check and let
	// patchAssignmentPolicy verify the actual Graph state.
	generation := obj.GetGeneration()
	expectedPatch := fmt.Sprintf("gen-%d-val-%s", generation, val)
	if !forceVerify {
		lastPatched := annotations[annotationLastPatched]
		if lastPatched == expectedPatch {
			klog.V(4).Infof("policy %s: already patched for %s, skipping", name, expectedPatch)
			return
		}
	}

	// Patch Graph API
	if err := graph.patchAssignmentPolicy(ctx, id, allowCustomSchedule); err != nil {
		klog.Errorf("policy %s (id=%s): Graph API patch failed: %v", name, id, err)
		return
	}

	// Update the annotation to record we patched this version
	annotations[annotationLastPatched] = expectedPatch
	obj.SetAnnotations(annotations)
	_, err = client.Resource(policyGVR).Update(ctx, obj, metav1.UpdateOptions{})
	if err != nil {
		klog.Warningf("policy %s: Graph patched but failed to update annotation: %v", name, err)
	}
}

// reconcileXR handles catalog resolution and group membership for an
// AccessPackageBundle XR.
func reconcileXR(ctx context.Context, client dynamic.Interface, graph *graphClient, obj *unstructured.Unstructured, forceVerify bool) {
	name := obj.GetName()
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	changed := false

	// ── 1. Catalog resolution ──────────────────────────────────────
	catalogName, _, _ := unstructured.NestedString(obj.Object, "spec", "catalogName")
	if catalogName != "" {
		existingID := annotations[annotationCatalogID]
		if existingID == "" || forceVerify {
			catalogID, err := graph.resolveCatalogName(ctx, catalogName)
			if err != nil {
				klog.Errorf("XR %s: failed to resolve catalog %q: %v", name, catalogName, err)
			} else if catalogID != existingID {
				klog.Infof("XR %s: resolved catalog %q → %s", name, catalogName, catalogID)
				annotations[annotationCatalogID] = catalogID
				changed = true
			}
		}
	}

	// ── 2. Group membership (systemOwner UPNs → approver group) ───
	approverGroupID, _, _ := unstructured.NestedString(obj.Object, "status", "approverGroupId")
	systemOwnerRaw, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "systemOwner")

	if approverGroupID != "" && len(systemOwnerRaw) > 0 {
		// Build fingerprint to detect changes
		fingerprint := fmt.Sprintf("%s:%s", approverGroupID, strings.Join(systemOwnerRaw, ","))
		lastSync := annotations[annotationMembersSync]

		if lastSync != fingerprint || forceVerify {
			// Get current members
			currentMembers, err := graph.getGroupMembers(ctx, approverGroupID)
			if err != nil {
				klog.Errorf("XR %s: failed to get group members: %v", name, err)
			} else {
				allResolved := true
				for _, upn := range systemOwnerRaw {
					userID, err := graph.resolveUPN(ctx, upn)
					if err != nil {
						klog.Errorf("XR %s: failed to resolve UPN %s: %v", name, upn, err)
						allResolved = false
						continue
					}
					if !currentMembers[userID] {
						if err := graph.addGroupMember(ctx, approverGroupID, userID); err != nil {
							klog.Errorf("XR %s: failed to add %s (%s) to group: %v", name, upn, userID, err)
							allResolved = false
						} else {
							klog.Infof("XR %s: added %s (%s) to approver group %s", name, upn, userID, approverGroupID)
						}
					}
				}
				if allResolved {
					annotations[annotationMembersSync] = fingerprint
					changed = true
				}
			}
		}
	}

	if changed {
		// Retry with re-fetch to handle conflicts from Crossplane reconciler
		for attempt := 0; attempt < 5; attempt++ {
			fresh, err := client.Resource(xrGVR).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				klog.Warningf("XR %s: failed to re-fetch for annotation update: %v", name, err)
				break
			}
			freshAnnotations := fresh.GetAnnotations()
			if freshAnnotations == nil {
				freshAnnotations = map[string]string{}
			}
			// Merge our annotations onto the fresh copy
			for _, key := range []string{annotationCatalogID, annotationMembersSync} {
				if v, ok := annotations[key]; ok {
					freshAnnotations[key] = v
				}
			}
			fresh.SetAnnotations(freshAnnotations)
			_, err = client.Resource(xrGVR).Update(ctx, fresh, metav1.UpdateOptions{})
			if err == nil {
				break
			}
			if strings.Contains(err.Error(), "the object has been modified") {
				klog.V(2).Infof("XR %s: conflict on attempt %d, retrying", name, attempt+1)
				time.Sleep(200 * time.Millisecond)
				continue
			}
			klog.Warningf("XR %s: failed to update annotations: %v", name, err)
			break
		}
	}
}

// watchResource runs a generic list-watch-resync loop.
// reconcileFn is called for each object; gvr is the resource to watch.
func watchResource(
	ctx context.Context,
	client dynamic.Interface,
	graph *graphClient,
	gvr schema.GroupVersionResource,
	label string,
	reconcileFn func(context.Context, dynamic.Interface, *graphClient, *unstructured.Unstructured, bool),
) error {
	resyncTicker := time.NewTicker(2 * time.Minute)
	defer resyncTicker.Stop()

	for {
		list, err := client.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("listing %s: %w", label, err)
		}
		for i := range list.Items {
			reconcileFn(ctx, client, graph, &list.Items[i], true)
		}

		watcher, err := client.Resource(gvr).Watch(ctx, metav1.ListOptions{
			ResourceVersion: list.GetResourceVersion(),
		})
		if err != nil {
			klog.Errorf("[%s] watch failed: %v, retrying in 5s", label, err)
			time.Sleep(5 * time.Second)
			continue
		}

	watchLoop:
		for {
			select {
			case event, ok := <-watcher.ResultChan():
				if !ok {
					klog.Infof("[%s] watch channel closed, restarting", label)
					break watchLoop
				}
				switch event.Type {
				case watch.Added, watch.Modified:
					obj, ok := event.Object.(*unstructured.Unstructured)
					if !ok {
						continue
					}
					reconcileFn(ctx, client, graph, obj, false)
				case watch.Error:
					klog.Errorf("[%s] watch error event, restarting", label)
					break watchLoop
				}
			case <-resyncTicker.C:
				klog.V(2).Infof("[%s] periodic re-sync", label)
				list, err := client.Resource(gvr).List(ctx, metav1.ListOptions{})
				if err != nil {
					klog.Errorf("[%s] re-sync list failed: %v", label, err)
					continue
				}
				for i := range list.Items {
					reconcileFn(ctx, client, graph, &list.Items[i], true)
				}
			case <-ctx.Done():
				watcher.Stop()
				return ctx.Err()
			}
		}

		time.Sleep(time.Second)
	}
}

func main() {
	klog.InitFlags(nil)

	graph, err := newGraphClient()
	if err != nil {
		klog.Fatalf("initializing Graph client: %v", err)
	}

	client, err := getKubeClient()
	if err != nil {
		klog.Fatalf("initializing kube client: %v", err)
	}

	klog.Info("graph-patcher starting")
	klog.Info("  → watching AccessPackageAssignmentPolicy (allowCustomAssignmentSchedule)")
	klog.Info("  → watching AccessPackageBundle XRs (catalog resolution, group membership)")
	ctx := context.Background()

	var wg sync.WaitGroup

	// Watch assignment policies (existing behavior)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := watchResource(ctx, client, graph, policyGVR, "policies", reconcile); err != nil {
			klog.Errorf("policy watcher exited: %v", err)
		}
	}()

	// Watch AccessPackageBundle XRs (catalog + membership)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := watchResource(ctx, client, graph, xrGVR, "XRs", reconcileXR); err != nil {
			klog.Errorf("XR watcher exited: %v", err)
		}
	}()

	wg.Wait()
	klog.Fatal("all watchers exited unexpectedly")
}
