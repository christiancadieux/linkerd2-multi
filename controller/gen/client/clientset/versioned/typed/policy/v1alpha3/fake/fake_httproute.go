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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha3 "github.com/linkerd/linkerd2/controller/gen/apis/policy/v1alpha3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeHTTPRoutes implements HTTPRouteInterface
type FakeHTTPRoutes struct {
	Fake *FakePolicyV1alpha3
	ns   string
}

var httproutesResource = v1alpha3.SchemeGroupVersion.WithResource("httproutes")

var httproutesKind = v1alpha3.SchemeGroupVersion.WithKind("HTTPRoute")

// Get takes name of the hTTPRoute, and returns the corresponding hTTPRoute object, and an error if there is any.
func (c *FakeHTTPRoutes) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha3.HTTPRoute, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(httproutesResource, c.ns, name), &v1alpha3.HTTPRoute{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha3.HTTPRoute), err
}

// List takes label and field selectors, and returns the list of HTTPRoutes that match those selectors.
func (c *FakeHTTPRoutes) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha3.HTTPRouteList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(httproutesResource, httproutesKind, c.ns, opts), &v1alpha3.HTTPRouteList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha3.HTTPRouteList{ListMeta: obj.(*v1alpha3.HTTPRouteList).ListMeta}
	for _, item := range obj.(*v1alpha3.HTTPRouteList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested hTTPRoutes.
func (c *FakeHTTPRoutes) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(httproutesResource, c.ns, opts))

}

// Create takes the representation of a hTTPRoute and creates it.  Returns the server's representation of the hTTPRoute, and an error, if there is any.
func (c *FakeHTTPRoutes) Create(ctx context.Context, hTTPRoute *v1alpha3.HTTPRoute, opts v1.CreateOptions) (result *v1alpha3.HTTPRoute, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(httproutesResource, c.ns, hTTPRoute), &v1alpha3.HTTPRoute{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha3.HTTPRoute), err
}

// Update takes the representation of a hTTPRoute and updates it. Returns the server's representation of the hTTPRoute, and an error, if there is any.
func (c *FakeHTTPRoutes) Update(ctx context.Context, hTTPRoute *v1alpha3.HTTPRoute, opts v1.UpdateOptions) (result *v1alpha3.HTTPRoute, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(httproutesResource, c.ns, hTTPRoute), &v1alpha3.HTTPRoute{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha3.HTTPRoute), err
}

// Delete takes name of the hTTPRoute and deletes it. Returns an error if one occurs.
func (c *FakeHTTPRoutes) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(httproutesResource, c.ns, name, opts), &v1alpha3.HTTPRoute{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeHTTPRoutes) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(httproutesResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha3.HTTPRouteList{})
	return err
}

// Patch applies the patch and returns the patched hTTPRoute.
func (c *FakeHTTPRoutes) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha3.HTTPRoute, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(httproutesResource, c.ns, name, pt, data, subresources...), &v1alpha3.HTTPRoute{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha3.HTTPRoute), err
}
