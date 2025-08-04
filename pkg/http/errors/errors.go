package errors

import (
	"errors"
)

var (
	ErrNilPathUrl                = errors.New("nil path url")
	ErrEmptyLocation             = errors.New("empty location")
	ErrNilSitemapXmlUrl          = errors.New("nil sitemap.xml url")
	ErrNilBaseUrl                = errors.New("nil base url")
	ErrNilSecurityTxtUrl         = errors.New("nil security.txt url")
	ErrNilDefaultHeaders         = errors.New("nil default headers")
	ErrNilDefaultDocumentHeaders = errors.New("nil default document headers")
	ErrEmptyDomain = errors.New("empty domain")
	ErrEmptyPort = errors.New("empty port")
)
