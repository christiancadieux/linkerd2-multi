/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by informer-gen. DO NOT EDIT.

package externalversions

import (
	"fmt"

	v1alpha1 "github.com/linkerd/linkerd2/controller/gen/apis/link/v1alpha1"
	policyv1alpha1 "github.com/linkerd/linkerd2/controller/gen/apis/policy/v1alpha1"
	v1alpha3 "github.com/linkerd/linkerd2/controller/gen/apis/policy/v1alpha3"
	v1beta1 "github.com/linkerd/linkerd2/controller/gen/apis/server/v1beta1"
	serverauthorizationv1beta1 "github.com/linkerd/linkerd2/controller/gen/apis/serverauthorization/v1beta1"
	v1alpha2 "github.com/linkerd/linkerd2/controller/gen/apis/serviceprofile/v1alpha2"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	cache "k8s.io/client-go/tools/cache"
)

// GenericInformer is type of SharedIndexInformer which will locate and delegate to other
// sharedInformers based on type
type GenericInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() cache.GenericLister
}

type genericInformer struct {
	informer cache.SharedIndexInformer
	resource schema.GroupResource
}

// Informer returns the SharedIndexInformer.
func (f *genericInformer) Informer() cache.SharedIndexInformer {
	return f.informer
}

// Lister returns the GenericLister.
func (f *genericInformer) Lister() cache.GenericLister {
	return cache.NewGenericLister(f.Informer().GetIndexer(), f.resource)
}

// ForResource gives generic access to a shared informer of the matching type
// TODO extend this to unknown resources with a client pool
func (f *sharedInformerFactory) ForResource(resource schema.GroupVersionResource) (GenericInformer, error) {
	switch resource {
	// Group=link, Version=v1alpha1
	case v1alpha1.SchemeGroupVersion.WithResource("links"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Link().V1alpha1().Links().Informer()}, nil

		// Group=linkerd.io, Version=v1alpha2
	case v1alpha2.SchemeGroupVersion.WithResource("serviceprofiles"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Linkerd().V1alpha2().ServiceProfiles().Informer()}, nil

		// Group=policy, Version=v1alpha1
	case policyv1alpha1.SchemeGroupVersion.WithResource("authorizationpolicies"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Policy().V1alpha1().AuthorizationPolicies().Informer()}, nil
	case policyv1alpha1.SchemeGroupVersion.WithResource("httproutes"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Policy().V1alpha1().HTTPRoutes().Informer()}, nil
	case policyv1alpha1.SchemeGroupVersion.WithResource("meshtlsauthentications"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Policy().V1alpha1().MeshTLSAuthentications().Informer()}, nil
	case policyv1alpha1.SchemeGroupVersion.WithResource("networkauthentications"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Policy().V1alpha1().NetworkAuthentications().Informer()}, nil

		// Group=policy, Version=v1alpha3
	case v1alpha3.SchemeGroupVersion.WithResource("httproutes"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Policy().V1alpha3().HTTPRoutes().Informer()}, nil

		// Group=server, Version=v1beta1
	case v1beta1.SchemeGroupVersion.WithResource("servers"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Server().V1beta1().Servers().Informer()}, nil

		// Group=serverauthorization, Version=v1beta1
	case serverauthorizationv1beta1.SchemeGroupVersion.WithResource("serverauthorizations"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Serverauthorization().V1beta1().ServerAuthorizations().Informer()}, nil

	}

	return nil, fmt.Errorf("no informer found for %v", resource)
}
