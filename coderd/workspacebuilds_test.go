package coderd_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/coder/coder/coderd"
	"github.com/coder/coder/coderd/coderdtest"
	"github.com/coder/coder/codersdk"
	"github.com/coder/coder/database"
	"github.com/coder/coder/provisioner/echo"
	"github.com/coder/coder/provisionersdk/proto"
)

func TestWorkspaceBuild(t *testing.T) {
	t.Parallel()
	client := coderdtest.New(t, nil)
	user := coderdtest.CreateFirstUser(t, client)
	coderdtest.NewProvisionerDaemon(t, client)
	version := coderdtest.CreateProjectVersion(t, client, user.OrganizationID, nil)
	project := coderdtest.CreateProject(t, client, user.OrganizationID, version.ID)
	coderdtest.AwaitProjectVersionJob(t, client, version.ID)
	workspace := coderdtest.CreateWorkspace(t, client, "me", project.ID)
	build, err := client.CreateWorkspaceBuild(context.Background(), workspace.ID, coderd.CreateWorkspaceBuildRequest{
		ProjectVersionID: project.ActiveVersionID,
		Transition:       database.WorkspaceTransitionStart,
	})
	require.NoError(t, err)
	_, err = client.WorkspaceBuild(context.Background(), build.ID)
	require.NoError(t, err)
}

func TestWorkspaceBuildResources(t *testing.T) {
	t.Parallel()
	t.Run("ListRunning", func(t *testing.T) {
		t.Parallel()
		client := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, client)
		closeDaemon := coderdtest.NewProvisionerDaemon(t, client)
		version := coderdtest.CreateProjectVersion(t, client, user.OrganizationID, nil)
		coderdtest.AwaitProjectVersionJob(t, client, version.ID)
		closeDaemon.Close()
		project := coderdtest.CreateProject(t, client, user.OrganizationID, version.ID)
		workspace := coderdtest.CreateWorkspace(t, client, "", project.ID)
		build, err := client.CreateWorkspaceBuild(context.Background(), workspace.ID, coderd.CreateWorkspaceBuildRequest{
			ProjectVersionID: project.ActiveVersionID,
			Transition:       database.WorkspaceTransitionStart,
		})
		require.NoError(t, err)
		_, err = client.WorkspaceResourcesByBuild(context.Background(), build.ID)
		var apiErr *codersdk.Error
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, http.StatusPreconditionFailed, apiErr.StatusCode())
	})
	t.Run("List", func(t *testing.T) {
		t.Parallel()
		client := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, client)
		coderdtest.NewProvisionerDaemon(t, client)
		version := coderdtest.CreateProjectVersion(t, client, user.OrganizationID, &echo.Responses{
			Parse: echo.ParseComplete,
			Provision: []*proto.Provision_Response{{
				Type: &proto.Provision_Response_Complete{
					Complete: &proto.Provision_Complete{
						Resources: []*proto.Resource{{
							Name: "some",
							Type: "example",
							Agent: &proto.Agent{
								Id:   "something",
								Auth: &proto.Agent_Token{},
							},
						}, {
							Name: "another",
							Type: "example",
						}},
					},
				},
			}},
		})
		coderdtest.AwaitProjectVersionJob(t, client, version.ID)
		project := coderdtest.CreateProject(t, client, user.OrganizationID, version.ID)
		workspace := coderdtest.CreateWorkspace(t, client, "", project.ID)
		build, err := client.CreateWorkspaceBuild(context.Background(), workspace.ID, coderd.CreateWorkspaceBuildRequest{
			ProjectVersionID: project.ActiveVersionID,
			Transition:       database.WorkspaceTransitionStart,
		})
		require.NoError(t, err)
		coderdtest.AwaitWorkspaceBuildJob(t, client, build.ID)
		resources, err := client.WorkspaceResourcesByBuild(context.Background(), build.ID)
		require.NoError(t, err)
		require.NotNil(t, resources)
		require.Len(t, resources, 2)
		require.Equal(t, "some", resources[0].Name)
		require.Equal(t, "example", resources[0].Type)
		require.NotNil(t, resources[0].Agent)
	})
}

func TestWorkspaceBuildLogs(t *testing.T) {
	t.Parallel()
	client := coderdtest.New(t, nil)
	user := coderdtest.CreateFirstUser(t, client)
	coderdtest.NewProvisionerDaemon(t, client)
	before := time.Now()
	version := coderdtest.CreateProjectVersion(t, client, user.OrganizationID, &echo.Responses{
		Parse: echo.ParseComplete,
		Provision: []*proto.Provision_Response{{
			Type: &proto.Provision_Response_Log{
				Log: &proto.Log{
					Level:  proto.LogLevel_INFO,
					Output: "example",
				},
			},
		}, {
			Type: &proto.Provision_Response_Complete{
				Complete: &proto.Provision_Complete{
					Resources: []*proto.Resource{{
						Name: "some",
						Type: "example",
						Agent: &proto.Agent{
							Id:   "something",
							Auth: &proto.Agent_Token{},
						},
					}, {
						Name: "another",
						Type: "example",
					}},
				},
			},
		}},
	})
	coderdtest.AwaitProjectVersionJob(t, client, version.ID)
	project := coderdtest.CreateProject(t, client, user.OrganizationID, version.ID)
	workspace := coderdtest.CreateWorkspace(t, client, "", project.ID)
	build, err := client.CreateWorkspaceBuild(context.Background(), workspace.ID, coderd.CreateWorkspaceBuildRequest{
		ProjectVersionID: project.ActiveVersionID,
		Transition:       database.WorkspaceTransitionStart,
	})
	require.NoError(t, err)
	ctx, cancelFunc := context.WithCancel(context.Background())
	t.Cleanup(cancelFunc)
	logs, err := client.WorkspaceBuildLogsAfter(ctx, build.ID, before)
	require.NoError(t, err)
	log := <-logs
	require.Equal(t, "example", log.Output)
}