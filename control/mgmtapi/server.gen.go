// Package mgmtapi provides primitives to interact with the openapi HTTP API.
//
// Code generated by unknown module path version unknown version DO NOT EDIT.
package mgmtapi

import (
	"fmt"
	"net/http"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/go-chi/chi/v5"
)

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// List the SCION beacons
	// (GET /beacons)
	GetBeacons(w http.ResponseWriter, r *http.Request, params GetBeaconsParams)
	// Get the SCION beacon description
	// (GET /beacons/{segment-id})
	GetBeacon(w http.ResponseWriter, r *http.Request, segmentId SegmentID)
	// Get the SCION beacon blob
	// (GET /beacons/{segment-id}/blob)
	GetBeaconBlob(w http.ResponseWriter, r *http.Request, segmentId SegmentID)
	// Information about the CA.
	// (GET /ca)
	GetCa(w http.ResponseWriter, r *http.Request)
	// List the certificate chains
	// (GET /certificates)
	GetCertificates(w http.ResponseWriter, r *http.Request, params GetCertificatesParams)
	// Get the certificate chain
	// (GET /certificates/{chain-id})
	GetCertificate(w http.ResponseWriter, r *http.Request, chainId ChainID)
	// Get the certificate chain blob
	// (GET /certificates/{chain-id}/blob)
	GetCertificateBlob(w http.ResponseWriter, r *http.Request, chainId ChainID)
	// Prints the TOML configuration file.
	// (GET /config)
	GetConfig(w http.ResponseWriter, r *http.Request)
	// Indicate the service health.
	// (GET /health)
	GetHealth(w http.ResponseWriter, r *http.Request)
	// Basic information page about the control service process.
	// (GET /info)
	GetInfo(w http.ResponseWriter, r *http.Request)
	// Get logging level
	// (GET /log/level)
	GetLogLevel(w http.ResponseWriter, r *http.Request)
	// Set logging level
	// (PUT /log/level)
	SetLogLevel(w http.ResponseWriter, r *http.Request)
	// List the SCION path segments
	// (GET /segments)
	GetSegments(w http.ResponseWriter, r *http.Request, params GetSegmentsParams)
	// Get the SCION path segment description
	// (GET /segments/{segment-id})
	GetSegment(w http.ResponseWriter, r *http.Request, segmentId SegmentID)
	// Get the SCION path segment blob
	// (GET /segments/{segment-id}/blob)
	GetSegmentBlob(w http.ResponseWriter, r *http.Request, segmentId SegmentID)
	// Prints information about the AS Certificate used to sign the control-plane message.
	// (GET /signer)
	GetSigner(w http.ResponseWriter, r *http.Request)
	// Get the certificate chain blob
	// (GET /signer/blob)
	GetSignerChain(w http.ResponseWriter, r *http.Request)
	// Prints the contents of the AS topology file.
	// (GET /topology)
	GetTopology(w http.ResponseWriter, r *http.Request)
	// List the TRCs
	// (GET /trcs)
	GetTrcs(w http.ResponseWriter, r *http.Request, params GetTrcsParams)
	// Get the TRC
	// (GET /trcs/isd{isd}-b{base}-s{serial})
	GetTrc(w http.ResponseWriter, r *http.Request, isd int, base int, serial int)
	// Get the TRC blob
	// (GET /trcs/isd{isd}-b{base}-s{serial}/blob)
	GetTrcBlob(w http.ResponseWriter, r *http.Request, isd int, base int, serial int)
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler            ServerInterface
	HandlerMiddlewares []MiddlewareFunc
	ErrorHandlerFunc   func(w http.ResponseWriter, r *http.Request, err error)
}

type MiddlewareFunc func(http.Handler) http.Handler

// GetBeacons operation middleware
func (siw *ServerInterfaceWrapper) GetBeacons(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// Parameter object where we will unmarshal all parameters from the context
	var params GetBeaconsParams

	// ------------- Optional query parameter "start_isd_as" -------------

	err = runtime.BindQueryParameter("form", true, false, "start_isd_as", r.URL.Query(), &params.StartIsdAs)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "start_isd_as", Err: err})
		return
	}

	// ------------- Optional query parameter "usages" -------------

	err = runtime.BindQueryParameter("form", true, false, "usages", r.URL.Query(), &params.Usages)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "usages", Err: err})
		return
	}

	// ------------- Optional query parameter "ingress_interface" -------------

	err = runtime.BindQueryParameter("form", true, false, "ingress_interface", r.URL.Query(), &params.IngressInterface)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "ingress_interface", Err: err})
		return
	}

	// ------------- Optional query parameter "valid_at" -------------

	err = runtime.BindQueryParameter("form", true, false, "valid_at", r.URL.Query(), &params.ValidAt)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "valid_at", Err: err})
		return
	}

	// ------------- Optional query parameter "all" -------------

	err = runtime.BindQueryParameter("form", true, false, "all", r.URL.Query(), &params.All)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "all", Err: err})
		return
	}

	// ------------- Optional query parameter "desc" -------------

	err = runtime.BindQueryParameter("form", true, false, "desc", r.URL.Query(), &params.Desc)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "desc", Err: err})
		return
	}

	// ------------- Optional query parameter "sort" -------------

	err = runtime.BindQueryParameter("form", true, false, "sort", r.URL.Query(), &params.Sort)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "sort", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetBeacons(w, r, params)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetBeacon operation middleware
func (siw *ServerInterfaceWrapper) GetBeacon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "segment-id" -------------
	var segmentId SegmentID

	err = runtime.BindStyledParameterWithLocation("simple", false, "segment-id", runtime.ParamLocationPath, chi.URLParam(r, "segment-id"), &segmentId)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "segment-id", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetBeacon(w, r, segmentId)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetBeaconBlob operation middleware
func (siw *ServerInterfaceWrapper) GetBeaconBlob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "segment-id" -------------
	var segmentId SegmentID

	err = runtime.BindStyledParameterWithLocation("simple", false, "segment-id", runtime.ParamLocationPath, chi.URLParam(r, "segment-id"), &segmentId)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "segment-id", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetBeaconBlob(w, r, segmentId)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetCa operation middleware
func (siw *ServerInterfaceWrapper) GetCa(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetCa(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetCertificates operation middleware
func (siw *ServerInterfaceWrapper) GetCertificates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// Parameter object where we will unmarshal all parameters from the context
	var params GetCertificatesParams

	// ------------- Optional query parameter "isd_as" -------------

	err = runtime.BindQueryParameter("form", true, false, "isd_as", r.URL.Query(), &params.IsdAs)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "isd_as", Err: err})
		return
	}

	// ------------- Optional query parameter "valid_at" -------------

	err = runtime.BindQueryParameter("form", true, false, "valid_at", r.URL.Query(), &params.ValidAt)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "valid_at", Err: err})
		return
	}

	// ------------- Optional query parameter "all" -------------

	err = runtime.BindQueryParameter("form", true, false, "all", r.URL.Query(), &params.All)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "all", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetCertificates(w, r, params)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetCertificate operation middleware
func (siw *ServerInterfaceWrapper) GetCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "chain-id" -------------
	var chainId ChainID

	err = runtime.BindStyledParameterWithLocation("simple", false, "chain-id", runtime.ParamLocationPath, chi.URLParam(r, "chain-id"), &chainId)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "chain-id", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetCertificate(w, r, chainId)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetCertificateBlob operation middleware
func (siw *ServerInterfaceWrapper) GetCertificateBlob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "chain-id" -------------
	var chainId ChainID

	err = runtime.BindStyledParameterWithLocation("simple", false, "chain-id", runtime.ParamLocationPath, chi.URLParam(r, "chain-id"), &chainId)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "chain-id", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetCertificateBlob(w, r, chainId)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetConfig operation middleware
func (siw *ServerInterfaceWrapper) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetConfig(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetHealth operation middleware
func (siw *ServerInterfaceWrapper) GetHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetHealth(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetInfo operation middleware
func (siw *ServerInterfaceWrapper) GetInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetInfo(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetLogLevel operation middleware
func (siw *ServerInterfaceWrapper) GetLogLevel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetLogLevel(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// SetLogLevel operation middleware
func (siw *ServerInterfaceWrapper) SetLogLevel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.SetLogLevel(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetSegments operation middleware
func (siw *ServerInterfaceWrapper) GetSegments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// Parameter object where we will unmarshal all parameters from the context
	var params GetSegmentsParams

	// ------------- Optional query parameter "start_isd_as" -------------

	err = runtime.BindQueryParameter("form", true, false, "start_isd_as", r.URL.Query(), &params.StartIsdAs)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "start_isd_as", Err: err})
		return
	}

	// ------------- Optional query parameter "end_isd_as" -------------

	err = runtime.BindQueryParameter("form", true, false, "end_isd_as", r.URL.Query(), &params.EndIsdAs)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "end_isd_as", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetSegments(w, r, params)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetSegment operation middleware
func (siw *ServerInterfaceWrapper) GetSegment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "segment-id" -------------
	var segmentId SegmentID

	err = runtime.BindStyledParameterWithLocation("simple", false, "segment-id", runtime.ParamLocationPath, chi.URLParam(r, "segment-id"), &segmentId)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "segment-id", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetSegment(w, r, segmentId)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetSegmentBlob operation middleware
func (siw *ServerInterfaceWrapper) GetSegmentBlob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "segment-id" -------------
	var segmentId SegmentID

	err = runtime.BindStyledParameterWithLocation("simple", false, "segment-id", runtime.ParamLocationPath, chi.URLParam(r, "segment-id"), &segmentId)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "segment-id", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetSegmentBlob(w, r, segmentId)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetSigner operation middleware
func (siw *ServerInterfaceWrapper) GetSigner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetSigner(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetSignerChain operation middleware
func (siw *ServerInterfaceWrapper) GetSignerChain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetSignerChain(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetTopology operation middleware
func (siw *ServerInterfaceWrapper) GetTopology(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetTopology(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetTrcs operation middleware
func (siw *ServerInterfaceWrapper) GetTrcs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// Parameter object where we will unmarshal all parameters from the context
	var params GetTrcsParams

	// ------------- Optional query parameter "isd" -------------

	err = runtime.BindQueryParameter("form", false, false, "isd", r.URL.Query(), &params.Isd)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "isd", Err: err})
		return
	}

	// ------------- Optional query parameter "all" -------------

	err = runtime.BindQueryParameter("form", true, false, "all", r.URL.Query(), &params.All)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "all", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetTrcs(w, r, params)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetTrc operation middleware
func (siw *ServerInterfaceWrapper) GetTrc(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "isd" -------------
	var isd int

	err = runtime.BindStyledParameterWithLocation("simple", false, "isd", runtime.ParamLocationPath, chi.URLParam(r, "isd"), &isd)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "isd", Err: err})
		return
	}

	// ------------- Path parameter "base" -------------
	var base int

	err = runtime.BindStyledParameterWithLocation("simple", false, "base", runtime.ParamLocationPath, chi.URLParam(r, "base"), &base)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "base", Err: err})
		return
	}

	// ------------- Path parameter "serial" -------------
	var serial int

	err = runtime.BindStyledParameterWithLocation("simple", false, "serial", runtime.ParamLocationPath, chi.URLParam(r, "serial"), &serial)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "serial", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetTrc(w, r, isd, base, serial)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetTrcBlob operation middleware
func (siw *ServerInterfaceWrapper) GetTrcBlob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "isd" -------------
	var isd int

	err = runtime.BindStyledParameterWithLocation("simple", false, "isd", runtime.ParamLocationPath, chi.URLParam(r, "isd"), &isd)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "isd", Err: err})
		return
	}

	// ------------- Path parameter "base" -------------
	var base int

	err = runtime.BindStyledParameterWithLocation("simple", false, "base", runtime.ParamLocationPath, chi.URLParam(r, "base"), &base)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "base", Err: err})
		return
	}

	// ------------- Path parameter "serial" -------------
	var serial int

	err = runtime.BindStyledParameterWithLocation("simple", false, "serial", runtime.ParamLocationPath, chi.URLParam(r, "serial"), &serial)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "serial", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetTrcBlob(w, r, isd, base, serial)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

type UnescapedCookieParamError struct {
	ParamName string
	Err       error
}

func (e *UnescapedCookieParamError) Error() string {
	return fmt.Sprintf("error unescaping cookie parameter '%s'", e.ParamName)
}

func (e *UnescapedCookieParamError) Unwrap() error {
	return e.Err
}

type UnmarshallingParamError struct {
	ParamName string
	Err       error
}

func (e *UnmarshallingParamError) Error() string {
	return fmt.Sprintf("Error unmarshalling parameter %s as JSON: %s", e.ParamName, e.Err.Error())
}

func (e *UnmarshallingParamError) Unwrap() error {
	return e.Err
}

type RequiredParamError struct {
	ParamName string
}

func (e *RequiredParamError) Error() string {
	return fmt.Sprintf("Query argument %s is required, but not found", e.ParamName)
}

type RequiredHeaderError struct {
	ParamName string
	Err       error
}

func (e *RequiredHeaderError) Error() string {
	return fmt.Sprintf("Header parameter %s is required, but not found", e.ParamName)
}

func (e *RequiredHeaderError) Unwrap() error {
	return e.Err
}

type InvalidParamFormatError struct {
	ParamName string
	Err       error
}

func (e *InvalidParamFormatError) Error() string {
	return fmt.Sprintf("Invalid format for parameter %s: %s", e.ParamName, e.Err.Error())
}

func (e *InvalidParamFormatError) Unwrap() error {
	return e.Err
}

type TooManyValuesForParamError struct {
	ParamName string
	Count     int
}

func (e *TooManyValuesForParamError) Error() string {
	return fmt.Sprintf("Expected one value for %s, got %d", e.ParamName, e.Count)
}

// Handler creates http.Handler with routing matching OpenAPI spec.
func Handler(si ServerInterface) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{})
}

type ChiServerOptions struct {
	BaseURL          string
	BaseRouter       chi.Router
	Middlewares      []MiddlewareFunc
	ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

// HandlerFromMux creates http.Handler with routing matching OpenAPI spec based on the provided mux.
func HandlerFromMux(si ServerInterface, r chi.Router) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseRouter: r,
	})
}

func HandlerFromMuxWithBaseURL(si ServerInterface, r chi.Router, baseURL string) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseURL:    baseURL,
		BaseRouter: r,
	})
}

// HandlerWithOptions creates http.Handler with additional options
func HandlerWithOptions(si ServerInterface, options ChiServerOptions) http.Handler {
	r := options.BaseRouter

	if r == nil {
		r = chi.NewRouter()
	}
	if options.ErrorHandlerFunc == nil {
		options.ErrorHandlerFunc = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
	wrapper := ServerInterfaceWrapper{
		Handler:            si,
		HandlerMiddlewares: options.Middlewares,
		ErrorHandlerFunc:   options.ErrorHandlerFunc,
	}

	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/beacons", wrapper.GetBeacons)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/beacons/{segment-id}", wrapper.GetBeacon)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/beacons/{segment-id}/blob", wrapper.GetBeaconBlob)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/ca", wrapper.GetCa)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/certificates", wrapper.GetCertificates)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/certificates/{chain-id}", wrapper.GetCertificate)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/certificates/{chain-id}/blob", wrapper.GetCertificateBlob)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/config", wrapper.GetConfig)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/health", wrapper.GetHealth)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/info", wrapper.GetInfo)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/log/level", wrapper.GetLogLevel)
	})
	r.Group(func(r chi.Router) {
		r.Put(options.BaseURL+"/log/level", wrapper.SetLogLevel)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/segments", wrapper.GetSegments)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/segments/{segment-id}", wrapper.GetSegment)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/segments/{segment-id}/blob", wrapper.GetSegmentBlob)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/signer", wrapper.GetSigner)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/signer/blob", wrapper.GetSignerChain)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/topology", wrapper.GetTopology)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/trcs", wrapper.GetTrcs)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/trcs/isd{isd}-b{base}-s{serial}", wrapper.GetTrc)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/trcs/isd{isd}-b{base}-s{serial}/blob", wrapper.GetTrcBlob)
	})

	return r
}
