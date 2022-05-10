package coderd_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coder/coder/coderd/coderdtest"
	"github.com/coder/coder/coderd/database"
	"github.com/coder/coder/codersdk"
	"github.com/coder/coder/provisioner/echo"
)

func TestTemplate(t *testing.T) {
	t.Parallel()

	t.Run("Get", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		version := coderdtest.CreateTemplateVersion(t, api.Client, user.OrganizationID, nil)
		template := coderdtest.CreateTemplate(t, api.Client, user.OrganizationID, version.ID)
		_, err := api.Client.Template(context.Background(), template.ID)
		require.NoError(t, err)
	})
}

func TestDeleteTemplate(t *testing.T) {
	t.Parallel()

	t.Run("NoWorkspaces", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		version := coderdtest.CreateTemplateVersion(t, api.Client, user.OrganizationID, nil)
		template := coderdtest.CreateTemplate(t, api.Client, user.OrganizationID, version.ID)
		err := api.Client.DeleteTemplate(context.Background(), template.ID)
		require.NoError(t, err)
	})

	t.Run("Workspaces", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		coderdtest.NewProvisionerDaemon(t, api.Client)
		version := coderdtest.CreateTemplateVersion(t, api.Client, user.OrganizationID, nil)
		template := coderdtest.CreateTemplate(t, api.Client, user.OrganizationID, version.ID)
		coderdtest.AwaitTemplateVersionJob(t, api.Client, version.ID)
		coderdtest.CreateWorkspace(t, api.Client, user.OrganizationID, template.ID)
		err := api.Client.DeleteTemplate(context.Background(), template.ID)
		var apiErr *codersdk.Error
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, http.StatusPreconditionFailed, apiErr.StatusCode())
	})
}

func TestTemplateVersionsByTemplate(t *testing.T) {
	t.Parallel()
	t.Run("Get", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		version := coderdtest.CreateTemplateVersion(t, api.Client, user.OrganizationID, nil)
		template := coderdtest.CreateTemplate(t, api.Client, user.OrganizationID, version.ID)
		versions, err := api.Client.TemplateVersionsByTemplate(context.Background(), codersdk.TemplateVersionsByTemplateRequest{
			TemplateID: template.ID,
		})
		require.NoError(t, err)
		require.Len(t, versions, 1)
	})
}

func TestTemplateVersionByName(t *testing.T) {
	t.Parallel()
	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		version := coderdtest.CreateTemplateVersion(t, api.Client, user.OrganizationID, nil)
		template := coderdtest.CreateTemplate(t, api.Client, user.OrganizationID, version.ID)
		_, err := api.Client.TemplateVersionByName(context.Background(), template.ID, "nothing")
		var apiErr *codersdk.Error
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, http.StatusNotFound, apiErr.StatusCode())
	})

	t.Run("Found", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		version := coderdtest.CreateTemplateVersion(t, api.Client, user.OrganizationID, nil)
		template := coderdtest.CreateTemplate(t, api.Client, user.OrganizationID, version.ID)
		_, err := api.Client.TemplateVersionByName(context.Background(), template.ID, version.Name)
		require.NoError(t, err)
	})
}

func TestPatchActiveTemplateVersion(t *testing.T) {
	t.Parallel()
	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		version := coderdtest.CreateTemplateVersion(t, api.Client, user.OrganizationID, nil)
		template := coderdtest.CreateTemplate(t, api.Client, user.OrganizationID, version.ID)
		err := api.Client.UpdateActiveTemplateVersion(context.Background(), template.ID, codersdk.UpdateActiveTemplateVersion{
			ID: uuid.New(),
		})
		var apiErr *codersdk.Error
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, http.StatusNotFound, apiErr.StatusCode())
	})

	t.Run("DoesNotBelong", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		version := coderdtest.CreateTemplateVersion(t, api.Client, user.OrganizationID, nil)
		template := coderdtest.CreateTemplate(t, api.Client, user.OrganizationID, version.ID)
		version = coderdtest.CreateTemplateVersion(t, api.Client, user.OrganizationID, nil)
		err := api.Client.UpdateActiveTemplateVersion(context.Background(), template.ID, codersdk.UpdateActiveTemplateVersion{
			ID: version.ID,
		})
		var apiErr *codersdk.Error
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, http.StatusUnauthorized, apiErr.StatusCode())
	})

	t.Run("Found", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		version := coderdtest.CreateTemplateVersion(t, api.Client, user.OrganizationID, nil)
		template := coderdtest.CreateTemplate(t, api.Client, user.OrganizationID, version.ID)
		err := api.Client.UpdateActiveTemplateVersion(context.Background(), template.ID, codersdk.UpdateActiveTemplateVersion{
			ID: version.ID,
		})
		require.NoError(t, err)
	})
}

// TestPaginatedTemplateVersions creates a list of template versions and paginate.
func TestPaginatedTemplateVersions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	api := coderdtest.New(t, &coderdtest.Options{APIRateLimit: -1})
	// Prepare database.
	user := coderdtest.CreateFirstUser(t, api.Client)
	coderdtest.NewProvisionerDaemon(t, api.Client)
	version := coderdtest.CreateTemplateVersion(t, api.Client, user.OrganizationID, nil)
	_ = coderdtest.AwaitTemplateVersionJob(t, api.Client, version.ID)
	template := coderdtest.CreateTemplate(t, api.Client, user.OrganizationID, version.ID)

	// Populate database with template versions.
	total := 9
	for i := 0; i < total; i++ {
		data, err := echo.Tar(nil)
		require.NoError(t, err)
		file, err := api.Client.Upload(context.Background(), codersdk.ContentTypeTar, data)
		require.NoError(t, err)
		templateVersion, err := api.Client.CreateTemplateVersion(ctx, user.OrganizationID, codersdk.CreateTemplateVersionRequest{
			TemplateID:    template.ID,
			StorageSource: file.Hash,
			StorageMethod: database.ProvisionerStorageMethodFile,
			Provisioner:   database.ProvisionerTypeEcho,
		})
		require.NoError(t, err)

		_ = coderdtest.AwaitTemplateVersionJob(t, api.Client, templateVersion.ID)
	}

	templateVersions, err := api.Client.TemplateVersionsByTemplate(ctx,
		codersdk.TemplateVersionsByTemplateRequest{
			TemplateID: template.ID,
		},
	)
	require.NoError(t, err)
	require.Len(t, templateVersions, 10, "wrong number of template versions created")

	type args struct {
		ctx        context.Context
		pagination codersdk.Pagination
	}
	tests := []struct {
		name string
		args args
		want []codersdk.TemplateVersion
	}{
		{
			name: "Single result",
			args: args{ctx: ctx, pagination: codersdk.Pagination{Limit: 1}},
			want: templateVersions[:1],
		},
		{
			name: "Single result, second page",
			args: args{ctx: ctx, pagination: codersdk.Pagination{Limit: 1, Offset: 1}},
			want: templateVersions[1:2],
		},
		{
			name: "Last two results",
			args: args{ctx: ctx, pagination: codersdk.Pagination{Limit: 2, Offset: 8}},
			want: templateVersions[8:10],
		},
		{
			name: "AfterID returns next two results",
			args: args{ctx: ctx, pagination: codersdk.Pagination{Limit: 2, AfterID: templateVersions[1].ID}},
			want: templateVersions[2:4],
		},
		{
			name: "No result after last AfterID",
			args: args{ctx: ctx, pagination: codersdk.Pagination{Limit: 2, AfterID: templateVersions[9].ID}},
			want: []codersdk.TemplateVersion{},
		},
		{
			name: "No result after last Offset",
			args: args{ctx: ctx, pagination: codersdk.Pagination{Limit: 2, Offset: 10}},
			want: []codersdk.TemplateVersion{},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := api.Client.TemplateVersionsByTemplate(tt.args.ctx, codersdk.TemplateVersionsByTemplateRequest{
				TemplateID: template.ID,
				Pagination: tt.args.pagination,
			})
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
