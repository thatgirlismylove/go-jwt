package main

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"time"
)

// jwt 密钥
var secretKey = []byte("secretKey")

type CustomClaims struct {
	Name string `json:"name"`
	jwt.RegisteredClaims
}

type User struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

func createToken(name string) (tokenString string, err error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, CustomClaims{
		Name: name,
		RegisteredClaims: jwt.RegisteredClaims{
			NotBefore: jwt.NewNumericDate(time.Now()), // 签名的生效时间
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			ID:        "1",
			Issuer:    "rookie", // 发行人，机构名称
		},
	})
	tokenString, err = token.SignedString(secretKey)
	return tokenString, err
}

func parseToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		fmt.Printf("error:%s", err.Error())
		fmt.Println()
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, jwt.ErrTokenMalformed
		} else if errors.Is(err, jwt.ErrInvalidKey) {
			return nil, jwt.ErrInvalidKey
		}
		// 更多错误类型请查看源码或者参考文档，此处省略
		return nil, jwt.ErrInvalidKey
	}
	if token != nil {
		if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
			return claims, nil
		}
		return nil, jwt.ErrInvalidKey
	} else {
		return nil, jwt.ErrInvalidKey
	}
}

func namePwdLogin(c *gin.Context) {
	var user User
	if err := c.ShouldBind(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
	tokenString, err := createToken(user.Name)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
	})
}

func userInfo(c *gin.Context) {
	tokenString := c.Request.Header.Get("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, map[string]string{
			"msg": "Missing authorization header",
		})
		return
	}
	tokenString = tokenString[len("Bearer "):]
	claims, err := parseToken(tokenString)
	if err != nil {
		fmt.Printf("error----: %s", err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, map[string]any{
		"name": claims.Name,
	})
}

func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	r.POST("/login", namePwdLogin)

	r.GET("/user", userInfo)

	addr := "0.0.0.0:8080"
	err := r.Run(addr)
	if err != nil {
		return
	}
	print("listening on " + addr)
	// listen and serve on 0.0.0.0:8080
}
