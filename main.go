// nativemons-submit: the submission service at submit.hails.app. It takes signed packages from the
// nativeMons launcher (Zakuro hint lists first), checks everything about them, and queues them for review.
//
//	nativemons-submit serve                        (NMSUBMIT_LISTEN, NMSUBMIT_DATA, NMSUBMIT_TRUST_PROXY=1)
//	nativemons-submit review list [approved|rejected]
//	nativemons-submit review show <receipt>
//	nativemons-submit review approve|reject <receipt>
//	nativemons-submit review ban <key id>
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	st, err := openStore(env("NMSUBMIT_DATA", "data"))
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: nativemons-submit serve | review ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		s := newServer(st, os.Getenv("NMSUBMIT_TRUST_PROXY") == "1")
		srv := &http.Server{
			Addr:              env("NMSUBMIT_LISTEN", "127.0.0.1:8087"),
			Handler:           s.routes(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       20 * time.Second,
			WriteTimeout:      20 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    8 << 10,
		}
		log.Printf("listening on %s", srv.Addr)
		log.Fatal(srv.ListenAndServe())
	case "review":
		os.Exit(review(st, os.Args[2:]))
	default:
		fmt.Fprintln(os.Stderr, "usage: nativemons-submit serve | review ...")
		os.Exit(2)
	}
}

func review(st *store, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "review list [approved|rejected] | show <receipt> | approve <receipt> | reject <receipt> | ban <key id>")
		return 2
	}
	switch {
	case args[0] == "list":
		where := "queue"
		if len(args) > 1 && (args[1] == "approved" || args[1] == "rejected") {
			where = args[1]
		}
		ms, err := st.list(where)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for _, m := range ms {
			fmt.Printf("%s  %s  key %s  %s\n", m.Receipt, m.Kind, m.Key, m.Summary)
		}
		return 0
	case args[0] == "show" && len(args) == 2 && reReceipt.MatchString(args[1]):
		// Printed as text for reading, after the same checks it passed on the way in.
		data, err := os.ReadFile(filepath.Join(st.dir, "queue", args[1]+".package"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		e, err := readEnvelope(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fails its checks now:", err)
			return 1
		}
		fmt.Printf("kind %s, launcher %q, zakuro %s, made %s\n%s\n", e.Kind, e.Launcher, e.Zakuro, e.Created, string(e.Body))
		return 0
	case (args[0] == "approve" || args[0] == "reject") && len(args) == 2:
		to := map[string]string{"approve": "approved", "reject": "rejected"}[args[0]]
		if err := st.move(args[1], to); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(args[1], "->", to)
		return 0
	case args[0] == "ban" && len(args) == 2:
		if err := st.ban(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("banned", args[1])
		return 0
	}
	fmt.Fprintln(os.Stderr, "review list [approved|rejected] | show <receipt> | approve <receipt> | reject <receipt> | ban <key id>")
	return 2
}
