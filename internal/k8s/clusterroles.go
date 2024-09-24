package k8s

import (
	"context"
	"fmt"
	"slices"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// NewClientSet creates a new Kubernetes clientset
func NewClientSet() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %v", err)
	}

	return kubernetes.NewForConfig(config)
}

// GetClusterRoles returns the ClusterRoles assigned to a provided service account name
func GetClusterRoles(ctx context.Context, client kubernetes.Interface, serviceAccountName string) ([]string, error) {
	clusterRoleBindings, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster role bindings: %v", err)
	}

	var clusterRoles []string
	for _, crb := range clusterRoleBindings.Items {
		for _, subject := range crb.Subjects {
			if slices.Contains([]string{rbacv1.UserKind, rbacv1.ServiceAccountKind}, subject.Kind) && subject.Name == serviceAccountName {
				clusterRoles = append(clusterRoles, crb.RoleRef.Name)
			}
		}
	}

	return clusterRoles, nil
}
