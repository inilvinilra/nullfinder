package storage

import (
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

// ScanRecord holds state about a specific scan execution.
type ScanRecord struct {
	ScanID    string    `json:"scan_id"`
	Domain    string    `json:"domain"`
	Mode      string    `json:"mode"`
	Timestamp time.Time `json:"timestamp"`
}

// AssetRecord groups passive/active metadata findings for a unique domain.
type AssetRecord struct {
	Domain            string   `json:"domain"`
	IPs               []string `json:"ips,omitempty"`
	CNAMEs            []string `json:"cnames,omitempty"`
	Ports             []int    `json:"ports,omitempty"`
	Schemes           []string `json:"schemes,omitempty"`
	FinalURLs         []string `json:"final_urls,omitempty"`
	StatusCodes       []int    `json:"status_codes,omitempty"`
	Titles            []string `json:"titles,omitempty"`
	Servers           []string `json:"servers,omitempty"`
	PoweredBy         []string `json:"powered_by,omitempty"`
	Technologies      []string `json:"technologies,omitempty"`
	FaviconHashes     []string `json:"favicon_hashes,omitempty"`
	CSPs              []string `json:"content_security_policies,omitempty"`
	HasLoginForm      bool     `json:"has_login_form"`
	TLSIssuers        []string `json:"tls_issuers,omitempty"`
	TLSExpiries       []string `json:"tls_expiries,omitempty"`
	IsInteresting     bool     `json:"is_interesting"`
	InterestingReason string   `json:"interesting_reason,omitempty"`
}

// BoltDB coordinates transactional updates to local database buckets.
type BoltDB struct {
	db *bbolt.DB
}

// NewBoltDB initializes a Bbolt connection.
func NewBoltDB(dbPath string) (*BoltDB, error) {
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open bbolt: %w", err)
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("scans"))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte("assets"))
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to create buckets: %w", err)
	}

	return &BoltDB{db: db}, nil
}

// Close releases the Bbolt file lock.
func (b *BoltDB) Close() {
	if b.db != nil {
		_ = b.db.Close()
	}
}

// SaveScan records basic metadata about the scan run.
func (b *BoltDB) SaveScan(scanID string, domain string, mode string) error {
	record := ScanRecord{
		ScanID:    scanID,
		Domain:    domain,
		Mode:      mode,
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(record)
	if err != nil {
		return err
	}

	return b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("scans"))
		return bucket.Put([]byte(scanID), data)
	})
}

// SaveAsset updates or creates a subdomain asset record under the scan prefix.
func (b *BoltDB) SaveAsset(scanID string, asset AssetRecord) error {
	data, err := json.Marshal(asset)
	if err != nil {
		return err
	}

	return b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("assets"))
		key := fmt.Sprintf("%s:%s", scanID, asset.Domain)
		return bucket.Put([]byte(key), data)
	})
}

// GetAssets fetches all saved subdomain assets matching a scanID.
func (b *BoltDB) GetAssets(scanID string) ([]AssetRecord, error) {
	var assets []AssetRecord

	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("assets"))
		c := bucket.Cursor()
		prefix := []byte(scanID + ":")

		for k, v := c.Seek(prefix); k != nil && len(k) >= len(prefix) && string(k[:len(prefix)]) == string(prefix); k, v = c.Next() {
			var asset AssetRecord
			if err := json.Unmarshal(v, &asset); err == nil {
				assets = append(assets, asset)
			}
		}
		return nil
	})

	return assets, err
}

// GetScan retrieves general info about a past scan.
func (b *BoltDB) GetScan(scanID string) (*ScanRecord, error) {
	var record ScanRecord
	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("scans"))
		data := bucket.Get([]byte(scanID))
		if data == nil {
			return fmt.Errorf("scan not found")
		}
		return json.Unmarshal(data, &record)
	})
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// ListScans returns all recorded scan metadata records.
func (b *BoltDB) ListScans() ([]ScanRecord, error) {
	var scans []ScanRecord
	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("scans"))
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			var scan ScanRecord
			if err := json.Unmarshal(v, &scan); err == nil {
				scans = append(scans, scan)
			}
			return nil
		})
	})
	return scans, err
}

// DeleteScan removes a scan metadata record and all its associated assets.
func (b *BoltDB) DeleteScan(scanID string) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		// 1. Delete scan metadata
		scansBucket := tx.Bucket([]byte("scans"))
		if scansBucket != nil {
			if err := scansBucket.Delete([]byte(scanID)); err != nil {
				return err
			}
		}

		// 2. Delete all matching assets
		assetsBucket := tx.Bucket([]byte("assets"))
		if assetsBucket != nil {
			c := assetsBucket.Cursor()
			prefix := []byte(scanID + ":")
			for k, _ := c.Seek(prefix); k != nil && len(k) >= len(prefix) && string(k[:len(prefix)]) == string(prefix); k, _ = c.Next() {
				if err := assetsBucket.Delete(k); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
