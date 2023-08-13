

# dev-192e6ba0-ccadie883

image:
	bin/docker-build
	docker images | grep linkerd | grep web | grep dev | grep ccadi| head -1 | awk '{print $$2}' > /tmp/linkerdid
	A=`cat /tmp/linkerdid`; docker tag cr.l5d.io/linkerd/web:$$A hub.comcast.net/k8s-eng/linkerd/web:stable-2.13.6-rdei
	docker push hub.comcast.net/k8s-eng/linkerd/web:stable-2.13.6-rdei
