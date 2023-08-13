

# dev-192e6ba0-ccadie883

image:
	bin/docker-build
	docker tag cr.l5d.io/linkerd/web:dev-192e6ba0-ccadie883 hub.comcast.net/k8s-eng/linkerd/web:stable-2.13.6-rdei
	docker push hub.comcast.net/k8s-eng/linkerd/web:stable-2.13.6-rdei
