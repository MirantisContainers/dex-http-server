package k8s_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/mirantiscontainers/dex-http-server/internal/k8s"
)

func TestGetClusterRoles(t *testing.T) {
	tests := []struct {
		name                string
		serviceAccountName  string
		clusterRoleBindings []rbacv1.ClusterRoleBinding
		expectedRoles       []string
		expectError         bool
	}{
		{
			name:               "Single cluster role for user account",
			serviceAccountName: "test-sa",
			clusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "binding1"},
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.UserKind, Name: "test-sa"},
					},
					RoleRef: rbacv1.RoleRef{Name: "role1"},
				},
			},
			expectedRoles: []string{"role1"},
			expectError:   false,
		},
		{
			name:               "Single cluster role for service account",
			serviceAccountName: "test-sa",
			clusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "binding1"},
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "test-sa"},
					},
					RoleRef: rbacv1.RoleRef{Name: "role1"},
				},
			},
			expectedRoles: []string{"role1"},
			expectError:   false,
		},
		{
			name:               "Multiple cluster roles for user account",
			serviceAccountName: "test-sa",
			clusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "binding1"},
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.UserKind, Name: "test-sa"},
					},
					RoleRef: rbacv1.RoleRef{Name: "role1"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "binding2"},
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.UserKind, Name: "test-sa"},
					},
					RoleRef: rbacv1.RoleRef{Name: "role2"},
				},
			},
			expectedRoles: []string{"role1", "role2"},
			expectError:   false,
		},
		{
			name:               "Multiple cluster roles for service account",
			serviceAccountName: "test-sa",
			clusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "binding1"},
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "test-sa"},
					},
					RoleRef: rbacv1.RoleRef{Name: "role1"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "binding2"},
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "test-sa"},
					},
					RoleRef: rbacv1.RoleRef{Name: "role2"},
				},
			},
			expectedRoles: []string{"role1", "role2"},
			expectError:   false,
		},
		{
			name:                "NoClusterRoleBindings",
			serviceAccountName:  "test-sa",
			clusterRoleBindings: []rbacv1.ClusterRoleBinding{},
			expectedRoles:       []string{},
			expectError:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewClientset(&rbacv1.ClusterRoleBindingList{
				Items: tt.clusterRoleBindings,
			})

			roles, err := k8s.GetClusterRoles(context.TODO(), clientset, tt.serviceAccountName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.ElementsMatch(t, tt.expectedRoles, roles)
			}
		})
	}
}
