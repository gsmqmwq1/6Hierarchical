import geoip2.database
import pandas as pd
import os
import time
import ipaddress
from multiprocessing import Pool


HEADER = ["ip", "country", "province", "city", "asnum", "asorg", "prefix", "network"]


def _lookup_with_readers(ipaddr, asdb, locdb, countrydb):
    result = {field: "notexist" for field in HEADER}
    result["ip"] = str(ipaddr).strip()

    try:
        ipaddress.IPv6Address(result["ip"])
    except (ipaddress.AddressValueError, ValueError):
        return result

    try:
        asinfo = asdb.asn(result["ip"])
        if asinfo.autonomous_system_number is not None:
            result["asnum"] = str(asinfo.autonomous_system_number)
        if asinfo.autonomous_system_organization:
            result["asorg"] = str(asinfo.autonomous_system_organization)
        if asinfo.network:
            result["prefix"] = str(asinfo.network)
    except Exception:
        pass

    try:
        locinfo = locdb.city(result["ip"])
        if locinfo.country.name:
            result["country"] = str(locinfo.country.name)
        if locinfo.subdivisions:
            province = locinfo.subdivisions[0].name
            if province:
                result["province"] = str(province)
        if locinfo.city.name:
            result["city"] = str(locinfo.city.name)
        if locinfo.traits.network:
            result["network"] = str(locinfo.traits.network)
    except Exception:
        pass

    if result["country"] == "notexist":
        try:
            country_info = countrydb.country(result["ip"])
            country = country_info.country.name or country_info.country.iso_code
            if country:
                result["country"] = str(country)
        except Exception:
            pass

    return result


class WhoisLookup:
    def __init__(self, asdb_path, locdb_path, countrydb_path):
        self._asdb = geoip2.database.Reader(asdb_path)
        self._locdb = geoip2.database.Reader(locdb_path)
        self._countrydb = geoip2.database.Reader(countrydb_path)
        self._closed = False

    def lookup(self, ipaddr):
        if self._closed:
            raise RuntimeError("WhoisLookup is already closed")
        return _lookup_with_readers(ipaddr, self._asdb, self._locdb, self._countrydb)

    def lookup_many(self, addresses):
        unique_addresses = []
        seen = set()
        for address in addresses:
            ipaddr = str(address).strip()
            if ipaddr and ipaddr not in seen:
                seen.add(ipaddr)
                unique_addresses.append(ipaddr)
        return [self.lookup(ipaddr) for ipaddr in unique_addresses]

    def close(self):
        if self._closed:
            return
        self._asdb.close()
        self._locdb.close()
        self._countrydb.close()
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASDB_PATH = os.path.join(BASE_DIR, "GeoLite2-ASN.mmdb")
LOCDB_PATH = os.path.join(BASE_DIR, "GeoLite2-City.mmdb")
COUNTRYDB_PATH = os.path.join(BASE_DIR, "GeoLite2-Country.mmdb")
INPUT_PATH = os.path.join(BASE_DIR, "input_ipv6.txt")
OUTPUT_PATH = os.path.join(BASE_DIR, "output_ipv6_metadata.csv")


def lookup_many(
    addresses, asdb_path=ASDB_PATH, locdb_path=LOCDB_PATH, countrydb_path=COUNTRYDB_PATH
):
    with WhoisLookup(asdb_path, locdb_path, countrydb_path) as lookup_tool:
        return lookup_tool.lookup_many(addresses)


_asdb = None
_locdb = None
_countrydb = None


def _init_worker():
    global _asdb, _locdb, _countrydb
    _asdb = geoip2.database.Reader(ASDB_PATH)
    _locdb = geoip2.database.Reader(LOCDB_PATH)
    _countrydb = geoip2.database.Reader(COUNTRYDB_PATH)


def addinfo(ipaddr):
    result = _lookup_with_readers(ipaddr, _asdb, _locdb, _countrydb)
    return [result[field] for field in HEADER]


if __name__ == "__main__":
    NUM_WORKERS = 16
    BATCH_SIZE = 200_000

    print("[1/3] Counting total rows...")
    with open(INPUT_PATH, "r") as f:
        total = sum(1 for line in f if line.strip())
    print(f"      Total {total:,}  IPv6 addresses")

    print(
        "[2/3] Starting lookup (16 parallel processes, with GeoLite2-Country.mmdb fallback)..."
    )
    start_time = time.time()

    pd.DataFrame(columns=HEADER).to_csv(OUTPUT_PATH, index=False, encoding="utf-8-sig")

    done = 0
    with open(INPUT_PATH, "r") as f:
        pool = Pool(processes=NUM_WORKERS, initializer=_init_worker)
        try:
            while True:
                batch = []
                for line in f:
                    ip = line.strip()
                    if ip:
                        batch.append(ip)
                    if len(batch) >= BATCH_SIZE:
                        break
                if not batch:
                    break

                results = pool.map(addinfo, batch)

                df_batch = pd.DataFrame(results, columns=HEADER)
                df_batch.to_csv(
                    OUTPUT_PATH,
                    mode="a",
                    header=False,
                    index=False,
                    encoding="utf-8-sig",
                )

                done += len(batch)
                elapsed = time.time() - start_time
                rate = done / elapsed if elapsed > 0 else 0
                eta = (total - done) / rate if rate > 0 else 0
                pct = done / total * 100
                print(
                    f"      Progress: {done:,}/{total:,} ({pct:.1f}%)  "
                    f"Rate: {rate:,.0f} IP/s  "
                    f"ETA: {eta / 60:.1f} minutes"
                )
        finally:
            pool.close()
            pool.join()

    elapsed = time.time() - start_time
    print(f"\n[3/3] Processing complete. Elapsed time: {elapsed / 60:.1f} minutes")
    print(f"      Output file: {OUTPUT_PATH}")

    print("\n===== Metadata coverage statistics =====")
    stats_total = 0
    stats_country = 0
    stats_province = 0
    stats_city = 0
    stats_notexist = 0
    stats_country_filled_by_countrydb = 0

    with open(OUTPUT_PATH, "r", encoding="utf-8-sig") as f:
        import csv

        reader = csv.DictReader(f)
        for row in reader:
            stats_total += 1
            c = row["country"]
            p = row["province"]
            ci = row["city"]

            if c and c != "notexist":
                stats_country += 1
            if p and p != "notexist":
                stats_province += 1
            if ci and ci != "notexist":
                stats_city += 1
            if c == "notexist" and p == "notexist" and ci == "notexist":
                stats_notexist += 1

    print(f"  Total records:      {stats_total:,}")
    print(
        f"  Country available:  {stats_country:,}  ({stats_country / stats_total * 100:.2f}%)"
    )
    print(
        f"  Province available: {stats_province:,}  ({stats_province / stats_total * 100:.2f}%)"
    )
    print(
        f"  City available:     {stats_city:,}  ({stats_city / stats_total * 100:.2f}%)"
    )
    print(
        f"  All fields missing:  {stats_notexist:,}  ({stats_notexist / stats_total * 100:.2f}%)"
    )
