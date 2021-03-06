FROM golang:1.9

RUN go get -u github.com/golang/dep/cmd/dep && go install github.com/golang/dep/cmd/dep

WORKDIR /go/src/github.com/iced-mocha/instagram-client
COPY . /go/src/github.com/iced-mocha/instagram-client

RUN dep ensure -v && go install -v

ENTRYPOINT ["instagram-client"]
