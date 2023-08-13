package srv

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/julienschmidt/httprouter"
	"github.com/linkerd/linkerd2/pkg/healthcheck"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/protohttp"
	metricsPb "github.com/linkerd/linkerd2/viz/metrics-api/gen/viz"
	vizUtil "github.com/linkerd/linkerd2/viz/metrics-api/util"
	tapPb "github.com/linkerd/linkerd2/viz/tap/gen/tap"
	tappkg "github.com/linkerd/linkerd2/viz/tap/pkg"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// Control Frame payload size can be no bigger than 125 bytes. 2 bytes are
// reserved for the status code when formatting the message.
const maxControlFrameMsgSize = 123

type (
	jsonError struct {
		Error string `json:"error"`
	}
)

var (
	defaultResourceType = k8s.Deployment
	pbMarshaler         = protojson.MarshalOptions{EmitUnpopulated: true}
	maxMessageSize      = 2048
	websocketUpgrader   = websocket.Upgrader{
		ReadBufferSize:  maxMessageSize,
		WriteBufferSize: maxMessageSize,
	}

	// Checks whose description matches the following regexp won't be included
	// in the handleApiCheck output. In the context of the dashboard, some
	// checks like cli or kubectl versions ones may not be relevant.
	//
	// TODO(tegioz): use more reliable way to identify the checks that should
	// not be displayed in the dashboard (hint anchor is not unique).
	excludedChecksRE = regexp.MustCompile(`(?i)cli|(?i)kubectl`)
)

func renderJSONError(w http.ResponseWriter, err error, status int) {
	w.Header().Set("Content-Type", "application/json")
	log.Error(err.Error())
	rsp, _ := json.Marshal(jsonError{Error: err.Error()})
	w.WriteHeader(status)
	w.Write(rsp)
}

func renderJSON(w http.ResponseWriter, resp interface{}) {
	w.Header().Set("Content-Type", "application/json")
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}
	w.Write(jsonResp)
}

func renderJSONPb(w http.ResponseWriter, msg proto.Message) {
	w.Header().Set("Content-Type", "application/json")
	json, err := pbMarshaler.Marshal(msg)
	if err != nil {
		renderJSONError(w, err, http.StatusBadRequest)
	}
	w.Write(json)
}

func renderJSONBytes(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (h *handler) handleAPIVersion(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	resp := map[string]interface{}{
		"version": h.version,
	}
	renderJSON(w, resp)
}

func (h *handler) handleAPIPods(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	pods, err := h.apiClient.ListPods(req.Context(), &metricsPb.ListPodsRequest{
		Selector: &metricsPb.ResourceSelection{
			Resource: &metricsPb.Resource{
				Namespace: req.FormValue("namespace"),
			},
		},
	})

	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}

	renderJSONPb(w, pods)
}

func (h *handler) handleAPIServices(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	services, err := h.apiClient.ListServices(req.Context(), &metricsPb.ListServicesRequest{
		Namespace: req.FormValue("namespace"),
	})

	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}

	renderJSONPb(w, services)
}

func setCookie(w http.ResponseWriter, name, value string) {
	expiration := time.Now().Add(1000 * time.Hour)
	cookie := http.Cookie{Name: name, Value: value, Expires: expiration}
	http.SetCookie(w, &cookie)
	log.Print(cookie)
}

const (
	SIDNAME = "lsid"
)

func processSessionId(w http.ResponseWriter, req *http.Request) string {
	queryValues := req.URL.Query()
	// fmt.Println("VALUES=", queryValues)
	sessionId := queryValues.Get(SIDNAME)
	fmt.Println("queryValue=", sessionId)
	if len(sessionId) != 36*2+1 {
		return ""
	}

	if sessionId != "" {
		// fmt.Printf("read %s=%s \n", SIDNAME, sessionId)
		setCookie(w, SIDNAME, sessionId)
	} else {
		idCookie, err := req.Cookie(SIDNAME)
		if err == nil {
			sessionId = idCookie.Value
			fmt.Println("Read Cookie", sessionId)
		} else {
			fmt.Println("FAILED TO READ COOKIE", err)
		}
	}
	return sessionId
}

func (h *handler) handleAPIStat(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	// Try to get stat summary from cache using the query as key

	locked := false
	if os.Getenv("RDEI_TENANT_LOCK") == "Y" {
		locked = true
	}
	sessionId := processSessionId(w, req)

	if locked && sessionId == "" {
		renderJSONError(w, fmt.Errorf("SessionId is required"), http.StatusInternalServerError)
		return
	}
	fmt.Println("sessionId=", sessionId)

	var err error
	allowedNamespaces := map[string]int{}
	if sessionId != "" {
		allowedNamespaces, err = loadAllowedNamespaces(sessionId)
		if err != nil {
			renderJSONError(w, fmt.Errorf("loadAllowedNamespaces %v", err), http.StatusInternalServerError)
			return
		}
	}
	fmt.Println("ALLOWED NAMESPACES=", len(allowedNamespaces))

	cachedResultJSON, ok := h.statCache.Get(req.URL.RawQuery)
	if ok {
		// Cache hit, render cached json result
		// fmt.Println("JSON=", string(cachedResultJSON.([]byte)))
		renderJSONBytes(w, cachedResultJSON.([]byte))
		return
	}

	trueStr := fmt.Sprintf("%t", true)

	requestParams := vizUtil.StatsSummaryRequestParams{
		StatsBaseRequestParams: vizUtil.StatsBaseRequestParams{
			TimeWindow:    req.FormValue("window"),
			ResourceName:  req.FormValue("resource_name"),
			ResourceType:  req.FormValue("resource_type"),
			Namespace:     req.FormValue("namespace"),
			AllNamespaces: req.FormValue("all_namespaces") == trueStr,
		},
		ToName:        req.FormValue("to_name"),
		ToType:        req.FormValue("to_type"),
		ToNamespace:   req.FormValue("to_namespace"),
		FromName:      req.FormValue("from_name"),
		FromType:      req.FormValue("from_type"),
		FromNamespace: req.FormValue("from_namespace"),
		SkipStats:     req.FormValue("skip_stats") == trueStr,
		TCPStats:      req.FormValue("tcp_stats") == trueStr,
	}

	// default to returning deployment stats
	if requestParams.ResourceType == "" {
		requestParams.ResourceType = defaultResourceType
	}
	fmt.Println("requestParams.ResourceType ", requestParams.ResourceType, "ns=", requestParams.Namespace)
	statRequest, err := vizUtil.BuildStatSummaryRequest(requestParams)

	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}

	result, err := h.apiClient.StatSummary(req.Context(), statRequest)

	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}

	// Marshal result into json and cache it
	json, err := pbMarshaler.Marshal(result)
	fmt.Println("CHECK SESSIONID", sessionId)
	if sessionId != "" {
		if requestParams.ResourceType == "namespace" && (requestParams.Namespace == "all" || requestParams.AllNamespaces) {
			json = filterNamespaces(allowedNamespaces, json)

		} else if !checkNS(allowedNamespaces, requestParams.Namespace) {
			renderJSONError(w, fmt.Errorf("Invalid Namespace"), http.StatusInternalServerError)
			return
		}
	}
	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}
	var resultJSON bytes.Buffer
	resultJSON.Write(json)

	h.statCache.SetDefault(req.URL.RawQuery, resultJSON.Bytes())

	renderJSONBytes(w, resultJSON.Bytes())
}

type ns struct {
	Ok struct {
		StatTables []struct {
			PodGroup struct {
				Rows []struct {
					Resource struct {
						Name string `json:"name"`
					} `json:"resource"`
				} `json:"rows"`
			} `json:"podGroup"`
		} `json:"statTables"`
	} `json:"ok"`
}

type podGroup struct {
	Rows []interface{} `json:"rows"`
}

type statTable struct {
	PodGroup podGroup `json:"podGroup"`
}
type okStruct struct {
	StatTables []statTable `json:"statTables"`
}

type ns0 struct {
	Ok okStruct `json:"ok"`
}

type TokenNamespaces struct {
	Namespaces []string `json:"namespaces"`
}

func rdeiGet(sessionId string) (*TokenNamespaces, error) {

	url := os.Getenv("RDEI_URL_NAMESPACE")
	if url == "" {
		url = "https://stage-api.rdei.comcast.net"
	}
	url += "/v1/tokens/namespaces/" + sessionId

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("Error creating Request. %s", err.Error())
	}
	token := os.Getenv("RDEI_TOKEN")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("rdeiGet: code=%v, url=%s, token=%s,  response: %s", resp.StatusCode, url, token, string(body))
	}

	out := &TokenNamespaces{}
	err = json.Unmarshal(body, &out)
	fmt.Printf("NAMESPACES=%+v \n", len(out.Namespaces))
	return out, nil
}

// VALIDATE NAMESPACES AGAINST RDEI

type nsList struct {
	Namespaces map[string]int
	LastUpdate time.Time
}

var AllowedNamespaces = map[string]nsList{}
var AllowedNamespacesLock sync.Mutex

func loadAllowedNamespaces(sessionId string) (map[string]int, error) {
	AllowedNamespacesLock.Lock()
	defer AllowedNamespacesLock.Unlock()

	// TRY CACHE
	if v, ok := AllowedNamespaces[sessionId]; ok {
		now := time.Now()
		if now.Sub(v.LastUpdate) < 10*time.Minute {
			// fmt.Printf("Using namespaces cache count= %+v \n", len(v.Namespaces))
			return v.Namespaces, nil
		}
	}

	namespaces, err := rdeiGet(sessionId)
	if err != nil {
		return nil, err
	}
	nslist := map[string]int{}
	for _, n := range namespaces.Namespaces {
		nslist[n] = 1
	}
	AllowedNamespaces[sessionId] = nsList{LastUpdate: time.Now(), Namespaces: nslist}
	// fmt.Printf("new nslist= %+v \n", len(nslist))
	return nslist, nil
}

func checkNS(allowedNamespaces map[string]int, ns string) bool {
	if ns == "" || ns == "all" {
		return true
	}
	if _, ok := allowedNamespaces[ns]; !ok {
		return true
	}
	return false
}

func filterNamespaces(allowedNamespaces map[string]int, res []byte) []byte {
	// fmt.Println("FILTER_RES=", string(res))
	nss := ns{}
	nss0 := ns0{}

	results := ns0{okStruct{}}
	results.Ok.StatTables = []statTable{}
	results.Ok.StatTables = append(results.Ok.StatTables, statTable{})
	results.Ok.StatTables[0].PodGroup.Rows = []interface{}{}

	err := json.Unmarshal(res, &nss)

	if err != nil {
		fmt.Println("filterNamespaces error", err)
		return res
	}
	err = json.Unmarshal(res, &nss0)

	if err != nil {
		fmt.Println("filterNamespaces error nss0", err)
		return res
	}

	if nss.Ok.StatTables == nil || len(nss.Ok.StatTables) == 0 {
		fmt.Println("filterNamespaces StatTables nil")
		return res
	}
	filteredRows := []interface{}{}
	for ix, ns := range nss.Ok.StatTables[0].PodGroup.Rows {
		if _, ok := allowedNamespaces[ns.Resource.Name]; !ok {
			continue
		}
		filteredRows = append(filteredRows, nss0.Ok.StatTables[0].PodGroup.Rows[ix])
		// results.Ok.StatTables[0].PodGroup.Rows = append(results.Ok.StatTables[0].PodGroup.Rows, nss0.Ok.StatTables[0].PodGroup.Rows[ix])
		// fmt.Println("Namespace=", ns.Resource.Name)
	}
	results.Ok.StatTables[0].PodGroup.Rows = filteredRows
	results_bytes, err := json.Marshal(results)
	if err != nil {
		fmt.Println("filterNamespaces error nss0", err)
		return res
	}
	return results_bytes
}

func (h *handler) handleAPITopRoutes(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	requestParams := vizUtil.TopRoutesRequestParams{
		StatsBaseRequestParams: vizUtil.StatsBaseRequestParams{
			TimeWindow:   req.FormValue("window"),
			ResourceName: req.FormValue("resource_name"),
			ResourceType: req.FormValue("resource_type"),
			Namespace:    req.FormValue("namespace"),
		},
		ToName:      req.FormValue("to_name"),
		ToType:      req.FormValue("to_type"),
		ToNamespace: req.FormValue("to_namespace"),
	}

	topReq, err := vizUtil.BuildTopRoutesRequest(requestParams)
	if err != nil {
		renderJSONError(w, err, http.StatusBadRequest)
		return
	}

	result, err := h.apiClient.TopRoutes(req.Context(), topReq)
	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}

	renderJSONPb(w, result)
}

// Control frame payload size must be no longer than `maxControlFrameMsgSize`
// bytes. In the case of an unexpected HTTP status code or unexpected error,
// truncate the message after `maxControlFrameMsgSize` bytes so that the web
// socket message is properly written.
func validateControlFrameMsg(err error) string {
	log.Debugf("tap error: %s", err.Error())

	msg := err.Error()
	if len(msg) > maxControlFrameMsgSize {
		return msg[:maxControlFrameMsgSize]
	}

	return msg
}

func websocketError(ws *websocket.Conn, wsError int, err error) {
	msg := validateControlFrameMsg(err)

	err = ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(wsError, msg),
		time.Time{})
	if err != nil {
		log.Errorf("Unexpected websocket error: %s", err)
	}
}

func (h *handler) handleAPITap(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	ws, err := websocketUpgrader.Upgrade(w, req, nil)
	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}
	defer ws.Close()

	messageType, message, err := ws.ReadMessage()
	if err != nil {
		websocketError(ws, websocket.CloseInternalServerErr, err)
		return
	}

	if messageType != websocket.TextMessage {
		websocketError(ws, websocket.CloseUnsupportedData, errors.New("messageType not supported"))
		return
	}

	var requestParams tappkg.TapRequestParams
	err = json.Unmarshal(message, &requestParams)
	if err != nil {
		websocketError(ws, websocket.CloseInternalServerErr, err)
		return
	}

	tapReq, err := tappkg.BuildTapByResourceRequest(requestParams)
	if err != nil {
		websocketError(ws, websocket.CloseInternalServerErr, err)
		return
	}

	go func() {
		reader, body, err := tappkg.Reader(req.Context(), h.k8sAPI, tapReq)
		if err != nil {
			// If there was a [403] error when initiating a tap, close the
			// socket with `ClosePolicyViolation` status code so that the error
			// renders without the error prefix in the banner
			var he protohttp.HTTPError
			if errors.Is(err, &he) && he.Code == http.StatusForbidden {
				err := fmt.Errorf("missing authorization, visit %s to remedy", tappkg.TapRbacURL)
				websocketError(ws, websocket.ClosePolicyViolation, err)
				return
			}

			// All other errors from initiating a tap should close with
			// `CloseInternalServerErr` status code
			websocketError(ws, websocket.CloseInternalServerErr, err)
			return
		}
		defer body.Close()

		for {
			event := tapPb.TapEvent{}
			err := protohttp.FromByteStreamToProtocolBuffers(reader, &event)
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				websocketError(ws, websocket.CloseInternalServerErr, err)
				break
			}

			json, err := pbMarshaler.Marshal(&event)
			if err != nil {
				websocketError(ws, websocket.CloseUnsupportedData, err)
				break
			}
			buf := new(bytes.Buffer)
			buf.Write(json)

			if err := ws.WriteMessage(websocket.TextMessage, buf.Bytes()); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure) {
					log.Error(err)
				}
				break
			}
		}
	}()

	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			log.Debugf("Received close frame: %v", err)
			if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure) {
				log.Errorf("Unexpected close error: %s", err)
			}
			return
		}
	}
}

func (h *handler) handleAPIEdges(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	requestParams := vizUtil.EdgesRequestParams{
		Namespace:    req.FormValue("namespace"),
		ResourceType: req.FormValue("resource_type"),
	}

	edgesRequest, err := vizUtil.BuildEdgesRequest(requestParams)
	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}

	result, err := h.apiClient.Edges(req.Context(), edgesRequest)
	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}
	renderJSONPb(w, result)
}

func (h *handler) handleAPICheck(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	type CheckResult struct {
		*healthcheck.CheckResult
		ErrMsg  string `json:",omitempty"`
		HintURL string `json:",omitempty"`
	}

	success := true
	results := make(map[healthcheck.CategoryID][]*CheckResult)

	collectResults := func(result *healthcheck.CheckResult) {
		if result.Retry || excludedChecksRE.MatchString(result.Description) {
			return
		}
		var errMsg, hintURL string
		if result.Err != nil {
			if !result.Warning {
				success = false
			}
			errMsg = result.Err.Error()
			hintURL = result.HintURL
		}
		results[result.Category] = append(results[result.Category], &CheckResult{
			CheckResult: result,
			ErrMsg:      errMsg,
			HintURL:     hintURL,
		})
	}
	// TODO (tegioz): ignore runchecks results until we stop filtering checks
	// in this method (see #3670 for more details)
	_, _ = h.hc.RunChecks(collectResults)

	renderJSON(w, map[string]interface{}{
		"success": success,
		"results": results,
	})
}

func (h *handler) handleAPIResourceDefinition(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	var missingParams []string
	requiredParams := []string{"namespace", "resource_type", "resource_name"}
	for _, param := range requiredParams {
		if req.FormValue(param) == "" {
			missingParams = append(missingParams, param)
		}
	}
	if len(missingParams) != 0 {
		renderJSONError(w, fmt.Errorf("required params not provided: %s", strings.Join(missingParams, ", ")), http.StatusBadRequest)
		return
	}

	namespace := req.FormValue("namespace")
	resourceType := req.FormValue("resource_type")
	resourceName := req.FormValue("resource_name")

	var resource interface{}
	var err error
	options := metav1.GetOptions{}
	switch resourceType {
	case k8s.CronJob:
		resource, err = h.k8sAPI.BatchV1beta1().CronJobs(namespace).Get(req.Context(), resourceName, options)
	case k8s.DaemonSet:
		resource, err = h.k8sAPI.AppsV1().DaemonSets(namespace).Get(req.Context(), resourceName, options)
	case k8s.Deployment:
		resource, err = h.k8sAPI.AppsV1().Deployments(namespace).Get(req.Context(), resourceName, options)
	case k8s.Service:
		resource, err = h.k8sAPI.CoreV1().Services(namespace).Get(req.Context(), resourceName, options)
	case k8s.Job:
		resource, err = h.k8sAPI.BatchV1().Jobs(namespace).Get(req.Context(), resourceName, options)
	case k8s.Pod:
		resource, err = h.k8sAPI.CoreV1().Pods(namespace).Get(req.Context(), resourceName, options)
	case k8s.ReplicationController:
		resource, err = h.k8sAPI.CoreV1().ReplicationControllers(namespace).Get(req.Context(), resourceName, options)
	case k8s.ReplicaSet:
		resource, err = h.k8sAPI.AppsV1().ReplicaSets(namespace).Get(req.Context(), resourceName, options)
	default:
		renderJSONError(w, errors.New("Invalid resource type: "+resourceType), http.StatusBadRequest)
		return
	}
	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}

	resourceDefinition, err := yaml.Marshal(resource)
	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/yaml")
	w.Write(resourceDefinition)
}

func (h *handler) handleGetExtensions(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	ctx := req.Context()
	extensionName := req.FormValue("extension_name")

	type Extension struct {
		Name      string `json:"name"`
		UID       string `json:"uid"`
		Namespace string `json:"namespace"`
	}

	resp := map[string]interface{}{}
	if extensionName != "" {
		ns, err := h.k8sAPI.GetNamespaceWithExtensionLabel(ctx, extensionName)
		if err != nil && kerrors.IsNotFound(err) {
			renderJSON(w, resp)
			return
		} else if err != nil {
			renderJSONError(w, err, http.StatusInternalServerError)
			return
		}

		resp["data"] = Extension{
			UID:       string(ns.UID),
			Name:      ns.GetLabels()[k8s.LinkerdExtensionLabel],
			Namespace: ns.Name,
		}

		renderJSON(w, resp)
		return
	}

	installedExtensions, err := h.k8sAPI.GetAllNamespacesWithExtensionLabel(ctx)
	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}

	extensionList := make([]Extension, len(installedExtensions))

	for i, installedExtension := range installedExtensions {
		extensionList[i] = Extension{
			UID:       string(installedExtension.GetObjectMeta().GetUID()),
			Name:      installedExtension.GetLabels()[k8s.LinkerdExtensionLabel],
			Namespace: installedExtension.GetName(),
		}
	}

	resp["extensions"] = extensionList
	renderJSON(w, resp)
}

func (h *handler) handleAPIGateways(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	window := req.FormValue("window")
	if window == "" {
		window = "1m"
	}
	_, err := time.ParseDuration(window)
	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}
	gatewayRequest := &metricsPb.GatewaysRequest{
		TimeWindow:        window,
		GatewayNamespace:  req.FormValue("gatewayNamespace"),
		RemoteClusterName: req.FormValue("remoteClusterName"),
	}
	result, err := h.apiClient.Gateways(req.Context(), gatewayRequest)
	if err != nil {
		renderJSONError(w, err, http.StatusInternalServerError)
		return
	}
	renderJSONPb(w, result)
}
