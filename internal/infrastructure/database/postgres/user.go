package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/SAP-2025/Auth-Service/internal/domain/entities"
	"github.com/SAP-2025/Auth-Service/internal/domain/repositories"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type userRepository struct {
	db *gorm.DB
}

func newUserRepository(db *gorm.DB) repositories.UserRepository {
	return &userRepository{db: db}
}

func (u userRepository) Create(ctx context.Context, user *entities.User) error {
	return u.db.WithContext(ctx).Create(user).Error
}

func (u userRepository) GetByID(ctx context.Context, id uuid.UUID) (*entities.User, error) {
	var user entities.User
	err := u.db.WithContext(ctx).
		Preload("Role").
		Preload("Role.Permissions").
		First(&user, "id = ?", id).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	return &user, nil
}

func (u userRepository) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	var user entities.User
	err := u.db.WithContext(ctx).
		Preload("Role").
		Preload("Role.Permissions").
		First(&user, "LOWER(email) = LOWER(?)", email).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	return &user, nil
}

func (u userRepository) GetByUsername(ctx context.Context, username string) (*entities.User, error) {
	var user entities.User
	err := u.db.WithContext(ctx).
		Preload("Role").
		Preload("Role.Permissions").
		First(&user, "LOWER(username) = LOWER(?)", username).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	return &user, nil
}

func (u userRepository) Update(ctx context.Context, user *entities.User) error {
	return u.db.WithContext(ctx).Save(user).Error
}

func (u userRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return u.db.WithContext(ctx).Delete(&entities.User{}, "id = ?", id).Error
}

func (u userRepository) GetBySocialID(ctx context.Context, provider, providerID string) (*entities.User, error) {
	var user entities.User
	var query string

	switch provider {
	case entities.ProviderGoogle:
		query = "google_id = ?"
	case entities.ProviderMicrosoft:
		query = "microsoft_id = ?"
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}

	err := u.db.WithContext(ctx).
		Preload("Role").
		Preload("Role.Permissions").
		First(&user, query, providerID).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	return &user, nil
}

func (u userRepository) LinkSocialAccount(ctx context.Context, socialAccount *entities.SocialAccount) error {
	return u.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(socialAccount).Error; err != nil {
			return err
		}

		var updateMap map[string]interface{}
		switch socialAccount.Provider {
		case entities.ProviderGoogle:
			updateMap = map[string]interface{}{
				"google_id": socialAccount.ProviderID,
			}
		case entities.ProviderMicrosoft:
			updateMap = map[string]interface{}{
				"microsoft_id": socialAccount.ProviderID,
			}
		default:
			return fmt.Errorf("unsupported provider: %s", socialAccount.Provider)
		}

		return tx.Model(&entities.User{}).
			Where("id = ?", socialAccount.UserID).
			Updates(updateMap).Error
	})
}

func (u userRepository) UnlinkSocialAccount(ctx context.Context, userID uuid.UUID, provider string) error {
	return u.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&entities.SocialAccount{}, "user_id = ? AND provider = ?", userID, provider).Error; err != nil {
			return err
		}

		var updateMap map[string]interface{}
		switch provider {
		case entities.ProviderGoogle:
			updateMap = map[string]interface{}{
				"google_id": nil,
			}
		case entities.ProviderMicrosoft:
			updateMap = map[string]interface{}{
				"microsoft_id": nil,
			}
		default:
			return fmt.Errorf("unsupported provider: %s", provider)
		}

		return tx.Model(&entities.User{}).
			Where("id = ?", userID).
			Updates(updateMap).Error
	})
}

func (u userRepository) GetSocialAccounts(ctx context.Context, userID uuid.UUID) ([]*entities.SocialAccount, error) {
	var socialAccount []*entities.SocialAccount
	err := u.db.WithContext(ctx).
		Where("user_id = ? AND is_active = true", userID).
		Order("created_at DESC").
		Find(&socialAccount).Error

	return socialAccount, err
}

func (u userRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	now := time.Now().UTC()
	return u.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"last_login_at": &now,
			"updated_at":    now,
		}).Error
}

func (u userRepository) SetMFASecret(ctx context.Context, userID uuid.UUID, secret string) error {
	return u.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("id = ?", userID).
		Update("mfa_secret", secret).Error
}

func (u userRepository) EnableMFA(ctx context.Context, userID uuid.UUID) error {
	return u.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("id = ?", userID).
		Update("mfa_enable", true).Error
}

func (u userRepository) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	return u.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"mfa_secret":   "",
			"mfa_enable":   false,
			"backup_codes": []string{},
		}).Error
}

func (u userRepository) SetBackupCodes(ctx context.Context, userID uuid.UUID, codes []string) error {
	return u.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("id = ?", userID).
		Update("backup_codes = ?", codes).Error
}

func (u userRepository) List(ctx context.Context, limit, offset int) ([]*entities.User, int, error) {
	var users []*entities.User
	var totalUser int64

	err := u.db.WithContext(ctx).Model(&entities.User{}).Count(&totalUser).Error
	if err != nil {
		return nil, 0, err
	}

	err = u.db.WithContext(ctx).
		Preload("Role").
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&users).Error

	return users, int(totalUser), err
}

func (u userRepository) Search(ctx context.Context, query string, limit, offset int) ([]*entities.User, int, error) {
	var users []*entities.User
	var totalUser int64

	// only search for username, email, firstname, lastname
	searchPattern := "%" + query + "%"
	searchCondition := u.db.Where("LOWER(username) LIKE LOWER(?) OR LOWER(email) LIKE LOWER(?) OR LOWER(first_name) LIKE LOWER(?) OR LOWER(last_name) LIKE LOWER(?)",
		searchPattern, searchPattern, searchPattern, searchPattern)

	err := searchCondition.Model(&entities.User{}).Count(&totalUser).Error
	if err != nil {
		return nil, 0, err
	}

	err = searchCondition.
		Preload("Role").
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&users).Error

	return users, int(totalUser), err
}

func (u userRepository) UpdateRole(ctx context.Context, userID, roleID uuid.UUID, reason string) error {
	return u.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("id = ?", userID).
		Update("role_id", roleID).Error
}

func (u userRepository) VerifyAccount(ctx context.Context, userID uuid.UUID) error {
	return u.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("id = ?", userID).
		Update("is_verified", true).Error
}

func (u userRepository) SetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	return u.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("id = ?", userID).
		Update("password_hash", passwordHash).Error
}
