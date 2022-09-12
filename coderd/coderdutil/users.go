package coderdutil

import (
	"context"

	"github.com/google/uuid"
	"golang.org/x/xerrors"

	"github.com/coder/coder/coderd/database"
	"github.com/coder/coder/coderd/gitsshkey"
	"github.com/coder/coder/coderd/rbac"
	"github.com/coder/coder/coderd/userpassword"
	"github.com/coder/coder/codersdk"
)

type CreateUserRequest struct {
	codersdk.CreateUserRequest
	LoginType          database.LoginType
	SSHKeygenAlgorithm gitsshkey.Algorithm
}

func CreateUser2(ctx context.Context, store database.Store, req CreateUserRequest) (database.User, uuid.UUID, error) {
	var user database.User
	return user, req.OrganizationID, store.InTx(func(tx database.Store) error {
		now := database.Now()
		orgRoles := make([]string, 0)
		// If no organization is provided, create a new one for the user.
		if req.OrganizationID == uuid.Nil {
			organization, err := tx.InsertOrganization(ctx, database.InsertOrganizationParams{
				ID:        uuid.New(),
				Name:      req.Username,
				CreatedAt: now,
				UpdatedAt: now,
			})
			if err != nil {
				return xerrors.Errorf("create organization: %w", err)
			}
			req.OrganizationID = organization.ID
			orgRoles = append(orgRoles, rbac.RoleOrgAdmin(req.OrganizationID))
		}

		params := database.InsertUserParams{
			ID:        uuid.New(),
			Email:     req.Email,
			Username:  req.Username,
			CreatedAt: now,
			UpdatedAt: now,
			// All new users are defaulted to members of the site.
			RBACRoles: []string{},
			LoginType: req.LoginType,
		}
		// If a user signs up with OAuth, they can have no password!
		if req.Password != "" {
			hashedPassword, err := userpassword.Hash(req.Password)
			if err != nil {
				return xerrors.Errorf("hash password: %w", err)
			}
			params.HashedPassword = []byte(hashedPassword)
		}

		var err error
		user, err = tx.InsertUser(ctx, params)
		if err != nil {
			return xerrors.Errorf("create user: %w", err)
		}

		privateKey, publicKey, err := gitsshkey.Generate(req.SSHKeygenAlgorithm)
		if err != nil {
			return xerrors.Errorf("generate user gitsshkey: %w", err)
		}
		_, err = tx.InsertGitSSHKey(ctx, database.InsertGitSSHKeyParams{
			UserID:     user.ID,
			CreatedAt:  now,
			UpdatedAt:  now,
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		})
		if err != nil {
			return xerrors.Errorf("insert user gitsshkey: %w", err)
		}
		_, err = tx.InsertOrganizationMember(ctx, database.InsertOrganizationMemberParams{
			OrganizationID: req.OrganizationID,
			UserID:         user.ID,
			CreatedAt:      now,
			UpdatedAt:      now,
			// By default give them membership to the organization.
			Roles: orgRoles,
		})
		if err != nil {
			return xerrors.Errorf("create organization member: %w", err)
		}
		return nil
	})
}
