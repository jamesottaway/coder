package coderd_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coder/coder/coderd/coderdtest"
	"github.com/coder/coder/coderd/database"
	"github.com/coder/coder/codersdk"
)

func TestPostParameter(t *testing.T) {
	t.Parallel()
	t.Run("BadScope", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		_, err := api.Client.CreateParameter(context.Background(), codersdk.ParameterScope("something"), user.OrganizationID, codersdk.CreateParameterRequest{
			Name:              "example",
			SourceValue:       "tomato",
			SourceScheme:      database.ParameterSourceSchemeData,
			DestinationScheme: database.ParameterDestinationSchemeProvisionerVariable,
		})
		var apiErr *codersdk.Error
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, http.StatusBadRequest, apiErr.StatusCode())
	})

	t.Run("Create", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		_, err := api.Client.CreateParameter(context.Background(), codersdk.ParameterOrganization, user.OrganizationID, codersdk.CreateParameterRequest{
			Name:              "example",
			SourceValue:       "tomato",
			SourceScheme:      database.ParameterSourceSchemeData,
			DestinationScheme: database.ParameterDestinationSchemeProvisionerVariable,
		})
		require.NoError(t, err)
	})

	t.Run("AlreadyExists", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		_, err := api.Client.CreateParameter(context.Background(), codersdk.ParameterOrganization, user.OrganizationID, codersdk.CreateParameterRequest{
			Name:              "example",
			SourceValue:       "tomato",
			SourceScheme:      database.ParameterSourceSchemeData,
			DestinationScheme: database.ParameterDestinationSchemeProvisionerVariable,
		})
		require.NoError(t, err)

		_, err = api.Client.CreateParameter(context.Background(), codersdk.ParameterOrganization, user.OrganizationID, codersdk.CreateParameterRequest{
			Name:              "example",
			SourceValue:       "tomato",
			SourceScheme:      database.ParameterSourceSchemeData,
			DestinationScheme: database.ParameterDestinationSchemeProvisionerVariable,
		})
		var apiErr *codersdk.Error
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, http.StatusConflict, apiErr.StatusCode())
	})
}

func TestParameters(t *testing.T) {
	t.Parallel()
	t.Run("ListEmpty", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		_, err := api.Client.Parameters(context.Background(), codersdk.ParameterOrganization, user.OrganizationID)
		require.NoError(t, err)
	})
	t.Run("List", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		_, err := api.Client.CreateParameter(context.Background(), codersdk.ParameterOrganization, user.OrganizationID, codersdk.CreateParameterRequest{
			Name:              "example",
			SourceValue:       "tomato",
			SourceScheme:      database.ParameterSourceSchemeData,
			DestinationScheme: database.ParameterDestinationSchemeProvisionerVariable,
		})
		require.NoError(t, err)
		params, err := api.Client.Parameters(context.Background(), codersdk.ParameterOrganization, user.OrganizationID)
		require.NoError(t, err)
		require.Len(t, params, 1)
	})
}

func TestDeleteParameter(t *testing.T) {
	t.Parallel()
	t.Run("NotExist", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		err := api.Client.DeleteParameter(context.Background(), codersdk.ParameterOrganization, user.OrganizationID, "something")
		var apiErr *codersdk.Error
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, http.StatusNotFound, apiErr.StatusCode())
	})
	t.Run("Delete", func(t *testing.T) {
		t.Parallel()
		api := coderdtest.New(t, nil)
		user := coderdtest.CreateFirstUser(t, api.Client)
		param, err := api.Client.CreateParameter(context.Background(), codersdk.ParameterOrganization, user.OrganizationID, codersdk.CreateParameterRequest{
			Name:              "example",
			SourceValue:       "tomato",
			SourceScheme:      database.ParameterSourceSchemeData,
			DestinationScheme: database.ParameterDestinationSchemeProvisionerVariable,
		})
		require.NoError(t, err)
		err = api.Client.DeleteParameter(context.Background(), codersdk.ParameterOrganization, user.OrganizationID, param.Name)
		require.NoError(t, err)
	})
}
