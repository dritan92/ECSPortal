package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/unrolled/render"
)

var rendering *render.Render
var store = sessions.NewCookieStore([]byte("session-key"))

func contains(dict map[string]string, i string) bool {
	if _, ok := dict[i]; ok {
		return true
	} else {
		return false
	}
}

func int64toString(value int64) string {
	return strconv.FormatInt(value, 10)
}

func int64InSlice(i int64, list []int64) bool {
	for _, value := range list {
		if value == i {
			return true
		}
	}
	return false
}

type appError struct {
	err      error
	status   int
	json     string
	template string
	binding  interface{}
}

type appHandler func(http.ResponseWriter, *http.Request) *appError

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e := fn(w, r); e != nil {
		log.Print(e.err)
		if e.status != 0 {
			if e.json != "" {
				rendering.JSON(w, e.status, e.json)
			} else {
				rendering.HTML(w, e.status, e.template, e.binding)
			}
		}
	}
}

func RecoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				http.Error(w, http.StatusText(500), 500)
			}
		}()

		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func LoginMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/app") {
			h.ServeHTTP(w, r)
		} else {
			session, err := store.Get(r, "session-name")
			if err != nil {
				rendering.HTML(w, http.StatusInternalServerError, "error", http.StatusInternalServerError)
			}
			if _, ok := session.Values["AccessKey"]; ok {
				h.ServeHTTP(w, r)
			} else {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			}
		}
	})
}

type ECS struct {
	Hostname  string `json:"hostname"`
	EndPoint  string `json:"endpoint"`
	Namespace string `json:"namespace"`
}

var hostname string

func main() {
	var port = ""
	// get all the environment data
	port = "8001" //os.Getenv("PORT")

	hostname, _ = os.Hostname()

	// See http://godoc.org/github.com/unrolled/render
	rendering = render.New(render.Options{Directory: "app/templates"})

	// See http://www.gorillatoolkit.org/pkg/mux
	router := mux.NewRouter()
	router.HandleFunc("/", Index)
	router.HandleFunc("/login", Login)
	router.HandleFunc("/api/v1/ecs", Ecs).Methods("GET")
	router.Handle("/api/v1/buckets", appHandler(Buckets)).Methods("GET")
	router.Handle("/api/v1/createbucket", appHandler(CreateBucket)).Methods("POST")
	router.PathPrefix("/app/").Handler(http.StripPrefix("/app/", http.FileServer(http.Dir("app"))))

	n := negroni.Classic()
	n.UseHandler(RecoverHandler(LoginMiddleware(router)))
	n.Run(":" + port)

	log.Printf("Listening on port " + port)
}

type UserSecretKeysResult struct {
	XMLName    xml.Name `xml:"user_secret_keys"`
	SecretKey1 string   `xml:"secret_key_1"`
	SecretKey2 string   `xml:"secret_key_2"`
}

type UserSecretKeyResult struct {
	XMLName   xml.Name `xml:"user_secret_key"`
	SecretKey string   `xml:"secret_key"`
}

type credentials struct {
	AccessKey  string
	SecretKey1 string
	SecretKey2 string
}

var tpl *template.Template

var ecs ECS

func init() {
	tpl = template.Must(template.ParseFiles("app/templates/index.tmpl"))
}

func Ecs(w http.ResponseWriter, r *http.Request) {
	rendering.JSON(w, http.StatusOK, ecs)
}

// Login using an AD or object user
func Login(w http.ResponseWriter, r *http.Request) {
	// If informaton received from the form
	if r.Method == "POST" {
		session, err := store.Get(r, "session-name")
		if err != nil {
			rendering.HTML(w, http.StatusInternalServerError, "error", http.StatusInternalServerError)
		}

		r.ParseForm()
		authentication := r.FormValue("authentication")
		user := r.FormValue("user")
		password := r.FormValue("password")
		endpoint := r.FormValue("endpoint")
		// For AD authentication, needs to retrieve the S3 secret key from ECS using the ECS management API
		if authentication == "ad" { //ktu ndodh  ekzekutimi i kodit
			url, err := url.Parse(endpoint)
			if err != nil {
				rendering.HTML(w, http.StatusOK, "login", "Check the endpoint")
			}
			hostname := url.Host
			if strings.Contains(hostname, ":") {
				hostname = strings.Split(hostname, ":")[0]
			}
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{Transport: tr}
			// Get an authentication token from ECS
			req, _ := http.NewRequest("GET", "https://"+hostname+":4443/login", nil)
			req.SetBasicAuth(user, password)
			resp, err := client.Do(req)
			if err != nil {
				log.Print(err)
			}
			if resp.StatusCode == 401 {
				rendering.HTML(w, http.StatusOK, "login", "Check your crententials and that you're allowed to generate a secret key on ECS")
			} else {
				// Get the secret key from ECS
				req, _ = http.NewRequest("GET", "https://"+hostname+":4443/object/secret-keys", nil)
				headers := map[string][]string{}
				headers["X-Sds-Auth-Token"] = []string{resp.Header.Get("X-Sds-Auth-Token")}
				req.Header = headers
				log.Print(headers)
				resp, err = client.Do(req)
				if err != nil {
					log.Print(err)
				}
				buf := new(bytes.Buffer)
				buf.ReadFrom(resp.Body)
				secretKey := ""
				userSecretKeysResult := &UserSecretKeysResult{}
				xml.NewDecoder(buf).Decode(userSecretKeysResult)
				secretKey = userSecretKeysResult.SecretKey1

				// If a secret key doesn't exist yet for this object user, needs to generate it
				if secretKey == "" {
					req, _ = http.NewRequest("POST", "https://"+hostname+":4443/object/secret-keys", bytes.NewBufferString("<secret_key_create_param></secret_key_create_param>"))
					headers["Content-Type"] = []string{"application/xml"}
					req.Header = headers
					resp, err = client.Do(req)
					if err != nil {
						log.Print(err)
					}
					buf = new(bytes.Buffer)
					buf.ReadFrom(resp.Body)
					userSecretKeyResult := &UserSecretKeyResult{}
					xml.NewDecoder(buf).Decode(userSecretKeyResult)
					secretKey = userSecretKeyResult.SecretKey
				}
				log.Print(secretKey)
				session.Values["AccessKey"] = user
				session.Values["SecretKey"] = secretKey
				session.Values["Endpoint"] = endpoint
				p := credentials{
					AccessKey:  user,
					SecretKey1: secretKey,
					SecretKey2: userSecretKeysResult.SecretKey2,
				}
				err = sessions.Save(r, w)
				if err != nil {
					rendering.HTML(w, http.StatusInternalServerError, "error", http.StatusInternalServerError)
				}
				rendering.HTML(w, http.StatusOK, "index", p)
			}
			// For an object user authentication, use the credentials as-is
		} else {
			session.Values["AccessKey"] = user
			session.Values["SecretKey"] = password
			session.Values["Endpoint"] = endpoint
			p := credentials{
				AccessKey:  user,
				SecretKey1: password,
				SecretKey2: "",
			}
			err = sessions.Save(r, w)
			if err != nil {
				rendering.HTML(w, http.StatusInternalServerError, "error", http.StatusInternalServerError)
			}
			rendering.HTML(w, http.StatusOK, "index", p)
		}
	} else {
		rendering.HTML(w, http.StatusOK, "login", nil)
	}
}

//get bucket list
func Buckets(w http.ResponseWriter, r *http.Request) *appError {
	session, err := store.Get(r, "session-name")
	if err != nil {
		return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
	}
	s3 := S3{
		EndPointString: ecs.EndPoint,
		AccessKey:      session.Values["AccessKey"].(string),
		SecretKey:      session.Values["SecretKey"].(string),
		Namespace:      ecs.Namespace,
	}
	response, _ := s3Request(s3, "", "GET", "/", make(map[string][]string), "")
	listBucketsResp := &ListBucketsResp{}
	xml.NewDecoder(strings.NewReader(response.Body)).Decode(listBucketsResp)
	buckets := []string{}
	for _, bucket := range listBucketsResp.Buckets {
		buckets = append(buckets, bucket.Name)
	}
	rendering.JSON(w, http.StatusOK, buckets)

	return nil
}

type NewBucket struct {
	Name      string `json:"bucket"`
	Encrypted bool   `json:"encrypted"`
}

// create bucket func.
func CreateBucket(w http.ResponseWriter, r *http.Request) *appError {
	session, err := store.Get(r, "session-name")
	if err != nil {
		return &appError{err: err, status: http.StatusInternalServerError, json: http.StatusText(http.StatusInternalServerError)}
	}
	s3 := S3{
		EndPointString: ecs.EndPoint,
		AccessKey:      session.Values["AccessKey"].(string),
		SecretKey:      session.Values["SecretKey"].(string),
		Namespace:      ecs.Namespace,
	}

	decoder := json.NewDecoder(r.Body)
	var bucket NewBucket
	err = decoder.Decode(&bucket)
	if err != nil {
		return &appError{err: err, status: http.StatusBadRequest, json: "Can't decode JSON data"}
	}

	// Add the necessary headers for Metadata Search and Access During Outage
	createBucketHeaders := map[string][]string{}
	createBucketHeaders["Content-Type"] = []string{"application/xml"}
	createBucketHeaders["x-emc-is-stale-allowed"] = []string{"true"}
	createBucketHeaders["x-emc-metadata-search"] = []string{"ObjectName,x-amz-meta-image-width;Integer,x-amz-meta-image-height;Integer,x-amz-meta-gps-latitude;Decimal,x-amz-meta-gps-longitude;Decimal"}

	createBucketResponse, _ := s3Request(s3, bucket.Name, "PUT", "/", createBucketHeaders, "")

	// Enable CORS after the bucket creation to allow the web browser to send requests directly to ECS
	if createBucketResponse.Code == 200 {
		enableBucketCorsHeaders := map[string][]string{}
		enableBucketCorsHeaders["Content-Type"] = []string{"application/xml"}
		corsConfiguration := `
		<CORSConfiguration>
		 <CORSRule>
		   <AllowedOrigin>*</AllowedOrigin>
		   <AllowedHeader>*</AllowedHeader>
		   <ExposeHeader>x-amz-meta-image-width</ExposeHeader>
		   <ExposeHeader>x-amz-meta-image-height</ExposeHeader>
		   <ExposeHeader>x-amz-meta-gps-latitude</ExposeHeader>
		   <ExposeHeader>x-amz-meta-gps-longitude</ExposeHeader>
		   <AllowedMethod>HEAD</AllowedMethod>
		   <AllowedMethod>GET</AllowedMethod>
		   <AllowedMethod>PUT</AllowedMethod>
		   <AllowedMethod>POST</AllowedMethod>
		   <AllowedMethod>DELETE</AllowedMethod>
		 </CORSRule>
		</CORSConfiguration>
	  `
		enableBucketCorsResponse, _ := s3Request(s3, bucket.Name, "PUT", "/?cors", enableBucketCorsHeaders, corsConfiguration)
		if enableBucketCorsResponse.Code == 200 {
			rendering.JSON(w, http.StatusOK, struct {
				CorsConfiguration string `json:"cors_configuration"`
				Bucket            string `json:"bucket"`
			}{
				CorsConfiguration: corsConfiguration,
				Bucket:            bucket.Name,
			})
		} else {
			return &appError{err: err, status: http.StatusBadRequest, json: "Bucket created, but CORS can't be enabled"}
		}
	} else {
		return &appError{err: err, status: http.StatusBadRequest, json: "Bucket can't be created"}
	}
	return nil
}

//main index function
func Index(w http.ResponseWriter, r *http.Request) {
	rendering.HTML(w, http.StatusOK, "login", nil)
}
