class SNIExtractor:
    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOSTNAME = 0x00

    @staticmethod
    def _read_uint16_be(data: bytes, offset: int) -> int:
        return (data[offset] << 8) | data[offset + 1]

    @staticmethod
    def _read_uint24_be(data: bytes, offset: int) -> int:
        return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]

    @staticmethod
    def is_tls_client_hello(payload: bytes) -> bool:
        length = len(payload)
        if length < 9:
            return False

        if payload[0] != SNIExtractor.CONTENT_TYPE_HANDSHAKE:
            return False

        version = SNIExtractor._read_uint16_be(payload, 1)
        if version < 0x0300 or version > 0x0304:
            return False

        record_length = SNIExtractor._read_uint16_be(payload, 3)
        if record_length > length - 5:
            return False

        if payload[5] != SNIExtractor.HANDSHAKE_CLIENT_HELLO:
            return False

        return True

    @staticmethod
    def extract(payload: bytes) -> str | None:
        if not SNIExtractor.is_tls_client_hello(payload):
            return None

        length = len(payload)
        offset = 5

        # Skip handshake header (4 bytes)
        _ = SNIExtractor._read_uint24_be(payload, offset + 1)
        offset += 4

        # Skip client version (2 bytes)
        offset += 2

        # Skip Random (32 bytes)
        offset += 32

        if offset >= length:
            return None
        session_id_length = payload[offset]
        offset += 1 + session_id_length

        if offset + 2 > length:
            return None
        cipher_suites_length = SNIExtractor._read_uint16_be(payload, offset)
        offset += 2 + cipher_suites_length

        if offset >= length:
            return None
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length

        if offset + 2 > length:
            return None
        extensions_length = SNIExtractor._read_uint16_be(payload, offset)
        offset += 2

        extensions_end = min(offset + extensions_length, length)

        while offset + 4 <= extensions_end:
            extension_type = SNIExtractor._read_uint16_be(payload, offset)
            extension_length = SNIExtractor._read_uint16_be(payload, offset + 2)
            offset += 4

            if offset + extension_length > extensions_end:
                break

            if extension_type == SNIExtractor.EXTENSION_SNI:
                if extension_length < 5:
                    break

                sni_list_length = SNIExtractor._read_uint16_be(payload, offset)
                if sni_list_length < 3:
                    break

                sni_type = payload[offset + 2]
                sni_length = SNIExtractor._read_uint16_be(payload, offset + 3)

                if sni_type != SNIExtractor.SNI_TYPE_HOSTNAME:
                    break
                if sni_length > extension_length - 5:
                    break

                try:
                    sni = payload[offset + 5 : offset + 5 + sni_length].decode("utf-8")
                    return sni
                except UnicodeDecodeError:
                    pass
                break

            offset += extension_length

        return None


class HTTPHostExtractor:
    @staticmethod
    def is_http_request(payload: bytes) -> bool:
        if len(payload) < 4:
            return False

        methods = [b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"]

        for method in methods:
            if payload[:4] == method:
                return True

        return False

    @staticmethod
    def extract(payload: bytes) -> str | None:
        if not HTTPHostExtractor.is_http_request(payload):
            return None

        length = len(payload)

        host_header_len = 6

        for i in range(length - host_header_len + 1):
            if payload[i : i + 6].lower() == b"host: ":
                start = i + 6
                while start < length and (
                    payload[start] == ord(" ") or payload[start] == ord("\t")
                ):
                    start += 1

                end = start
                while (
                    end < length
                    and payload[end] != ord("\r")
                    and payload[end] != ord("\n")
                ):
                    end += 1

                if end > start:
                    host_bytes = payload[start:end]
                    try:
                        host = host_bytes.decode("utf-8")
                        colon_pos = host.find(":")
                        if colon_pos != -1:
                            host = host[:colon_pos]
                        return host
                    except UnicodeDecodeError:
                        return None
        return None


class DNSExtractor:
    @staticmethod
    def is_dns_query(payload: bytes) -> bool:
        if len(payload) < 12:
            return False

        flags = payload[2]
        if flags & 0x80:
            return False

        qdcount = (payload[4] << 8) | payload[5]
        if qdcount == 0:
            return False

        return True

    @staticmethod
    def extract_query(payload: bytes) -> str | None:
        if not DNSExtractor.is_dns_query(payload):
            return None

        length = len(payload)
        offset = 12
        domain_parts = []

        while offset < length:
            label_length = payload[offset]

            if label_length == 0:
                break

            if label_length > 63:
                break

            offset += 1
            if offset + label_length > length:
                break

            try:
                part = payload[offset : offset + label_length].decode("utf-8")
                domain_parts.append(part)
            except UnicodeDecodeError:
                break

            offset += label_length

        if domain_parts:
            return ".".join(domain_parts)
        return None
