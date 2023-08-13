UI: http://10.54.213.147:8084/namespaces


when UI url is used with a lsid=.. , the UI will only show the namespace that are allowed by this lsid.
The lsid is the user toked used to access the RDEi UI and the facility_id of the cluster .

Ex: 
Linkerd UI: /namespaces?lsid=99fa05db-8df9-4a32-93c8-a9fd5f976489-88d40e18-da23-41f8-b886-fca67688c6dd

Linkerd API: /api/tps-reports?resource_type=namespace&namespace=all&tcp_stats=true&lsid=99fa05db-8df9-4a32-93c8-a9fd5f976489-88d40e18-da23-41f8-b886-fca67688c6dd&window=1m

RDEI API: /v1/tokens/namespaces/99fa05db-8df9-4a32-93c8-a9fd5f976489-88d40e18-da23-41f8-b886-fca67688c6dd

When the lsid is missing:
 - if RDEI_TENANT_LOCK=Y, the Linkerd API will fail.
 - if RDEI_TENANT_LOCK=N, the linkerd API will return all namespaces (super-user access).


Use these 2 images:
policy-controller:  Modified to include the cluster CA
     hub.comcast.net/k8s-eng/linkerd/policy-controller:stable-2.13.6-rdei

viz - web:
     hub.comcast.net/k8s-eng/linkerd/web:stable-2.13.6-rdei
     command: 
        docker tag cr.l5d.io/linkerd/web:dev-e61c4b51-ccadie883 hub.comcast.net/k8s-eng/linkerd/web:stable-2.13.6-rdei
        docker push hub.comcast.net/k8s-eng/linkerd/web:stable-2.13.6-rdei
             

