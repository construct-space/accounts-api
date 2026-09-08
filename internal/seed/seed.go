package seed

import (
	"log"

	"construct/accounts/internal/database"
	"construct/accounts/internal/models"
)

func Run() {
	seedOAuthClients()
	backfillUUIDs()
}

// backfillUUIDs generates UUIDs for any existing users that don't have one,
// then ensures the unique index exists.
func backfillUUIDs() {
	var users []models.User
	database.DB.Where("uuid = '' OR uuid IS NULL").Find(&users)
	for _, u := range users {
		uuid := models.GenerateUUID()
		database.DB.Model(&u).Update("uuid", uuid)
		log.Printf("[seed] Backfilled UUID for user %d: %s", u.ID, uuid)
	}

	// Now safe to add unique index (all rows have non-empty UUIDs)
	if !database.DB.Migrator().HasIndex(&models.User{}, "idx_users_uuid") {
		if err := database.DB.Migrator().CreateIndex(&models.User{}, "UUID"); err != nil {
			log.Printf("[seed] Note: UUID index may already exist: %v", err)
		} else {
			log.Println("[seed] Created unique index on users.uuid")
		}
	}
}

func seedOAuthClients() {
	clients := []struct {
		ClientID    string
		Name        string
		RedirectURI string
		Description string
	}{
		{"construct_my", "my.lisaos.dev", "https://my.lisaos.dev/oauth/callback", "Construct unified portal"},
		{"construct_app", "Construct", "construct://oauth/callback", "The Construct desktop application"},
		{"construct_teams", "Construct Teams", "construct-teams://oauth/callback", "Construct Teams desktop application"},
		{"spaces_portal", "Construct Spaces", "http://localhost:3001/api/auth/callback", "The Construct Spaces registry"},
		{"construct_website", "Construct Website", "http://localhost:3000/api/auth/callback", "The Construct website and dashboard"},
		{"construct_blog", "Construct Blog", "https://construct.blog/auth/callback", "The Construct Blog comments"},
		{"construct_delivery", "ConstructDelivery", "https://delivery.lisaos.dev/api/auth/callback", "ConstructDelivery email platform"},
	}

	for _, c := range clients {
		var count int64
		database.DB.Model(&models.OAuthClient{}).Where("client_id = ?", c.ClientID).Count(&count)
		if count == 0 {
			desc := c.Description
			database.DB.Create(&models.OAuthClient{
				ClientID:     c.ClientID,
				ClientSecret: models.GenerateClientSecret(),
				Name:         c.Name,
				RedirectURI:  c.RedirectURI,
				Description:  &desc,
				Active:       true,
			})
			log.Printf("[seed] Created OAuth client: %s", c.ClientID)
		}
	}
}
