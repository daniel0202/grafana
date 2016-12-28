package login

import (
	"net/url"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/log"
	"github.com/grafana/grafana/pkg/middleware"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
	"github.com/lucasuyezu/golang-cas-client"
)

func loginUserWithCas(user *m.User, c *middleware.Context) {
	if user == nil {
		log.Error(3, "User login with nil user")
	}

	days := 86400 * setting.LogInRememberDays
	c.SetCookie(setting.CookieUserName, user.Login, days, setting.AppSubUrl+"/")
	c.SetSuperSecureCookie(util.EncodeMd5(user.Rands+user.Password), setting.CookieRememberName, user.Login, days, setting.AppSubUrl+"/")

	c.Session.Set(middleware.SESS_KEY_USERID, user.Id)
}

func GetService() string {
	return setting.AppUrl + "login"
}

func CasLogin(c *middleware.Context) {

	service := GetService()

	ticket := c.Query("ticket")
	if len(ticket) == 0 {
		c.Redirect(setting.AuthCasServerUrl + "/login?service=" + service)
		return
	}

	cas := cas.NewService(setting.AuthCasServerUrl, service)
	response, _ := cas.ValidateServiceTicket(ticket)
	if response.Status {

		userQuery := m.GetUserByLoginQuery{LoginOrEmail: response.User}
		err := bus.Dispatch(&userQuery)

		if err != nil {
			cmd := m.CreateUserCommand{
				Email:    response.Email,
				Name:     response.User,
				Login:    response.User,
				Password: "",
			}
			if err := bus.Dispatch(&cmd); err != nil {
				c.JsonApiErr(500, "failed to create user", err)
				return
			}
			bus.Dispatch(&userQuery)
		}

		user := userQuery.Result
		loginUserWithCas(user, c)

		if redirectTo, _ := url.QueryUnescape(c.GetCookie("redirect_to")); len(redirectTo) > 0 {
			c.SetCookie("redirect_to", "", -1, setting.AppSubUrl+"/")
			c.Redirect(redirectTo)
			return
		}

		c.Redirect(setting.AppSubUrl + "/")
	} else {
		c.Redirect("/")
	}
}
