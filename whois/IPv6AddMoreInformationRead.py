import geoip2.database
import ipaddress


HEADER = ['ip', 'country', 'province', 'city',
          'asnum', 'asorg', 'prefix', 'network']


def _lookup_with_readers(ipaddr, asdb, locdb, countrydb):
    result = {field: 'notexist' for field in HEADER}
    result['ip'] = str(ipaddr).strip()

    try:
        ipaddress.IPv6Address(result['ip'])
    except (ipaddress.AddressValueError, ValueError):
        return result

    try:
        asinfo = asdb.asn(result['ip'])
        if asinfo.autonomous_system_number is not None:
            result['asnum'] = str(asinfo.autonomous_system_number)
        if asinfo.autonomous_system_organization:
            result['asorg'] = str(asinfo.autonomous_system_organization)
        if asinfo.network:
            result['prefix'] = str(asinfo.network)
    except Exception:
        pass

    try:
        locinfo = locdb.city(result['ip'])
        if locinfo.country.name:
            result['country'] = str(locinfo.country.name)
        if locinfo.subdivisions:
            province = locinfo.subdivisions[0].name
            if province:
                result['province'] = str(province)
        if locinfo.city.name:
            result['city'] = str(locinfo.city.name)
        if locinfo.traits.network:
            result['network'] = str(locinfo.traits.network)
    except Exception:
        pass

    if result['country'] == 'notexist':
        try:
            country_info = countrydb.country(result['ip'])
            country = country_info.country.name or country_info.country.iso_code
            if country:
                result['country'] = str(country)
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
            raise RuntimeError('WhoisLookup is closed')
        return _lookup_with_readers(
            ipaddr, self._asdb, self._locdb, self._countrydb
        )

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


def lookup_many(addresses, asdb_path, locdb_path, countrydb_path):
    """Open the GeoIP readers once and look up a batch of IPv6 addresses."""
    with WhoisLookup(asdb_path, locdb_path, countrydb_path) as lookup_tool:
        return lookup_tool.lookup_many(addresses)
