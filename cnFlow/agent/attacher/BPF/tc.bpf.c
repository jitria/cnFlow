#include "common.h"

// Protocol Types
#define PROTO_HTTP 1
#define PROTO_HTTP2 2
#define PROTO_KAFKA 3
#define PROTO_REDIS 4
#define PROTO_ICMP 5
#define PROTO_DNS 6
#define PROTO_TCP 7
#define PROTO_UNKNOWN 0

// HTTP/2 Frame Types
#define HTTP2_FRAME_DATA          0x0
#define HTTP2_FRAME_HEADERS       0x1
#define HTTP2_FRAME_PRIORITY      0x2
#define HTTP2_FRAME_RST_STREAM    0x3
#define HTTP2_FRAME_SETTINGS      0x4
#define HTTP2_FRAME_PUSH_PROMISE  0x5
#define HTTP2_FRAME_PING          0x6
#define HTTP2_FRAME_GOAWAY        0x7
#define HTTP2_FRAME_WINDOW_UPDATE 0x8
#define HTTP2_FRAME_CONTINUATION  0x9

// HTTP/2 Frame Flags
#define HTTP2_FLAG_END_STREAM     0x1
#define HTTP2_FLAG_END_HEADERS    0x4
#define HTTP2_FLAG_PADDED         0x8
#define HTTP2_FLAG_PRIORITY       0x20

// Redis command types
#define REDIS_CMD_GET       1
#define REDIS_CMD_SET       2
#define REDIS_CMD_PING      3
#define REDIS_CMD_HGET      4
#define REDIS_CMD_HSET      5
#define REDIS_CMD_SADD      6
#define REDIS_CMD_ZADD      7
#define REDIS_CMD_INFO      8
#define REDIS_CMD_ZRANGE    9
#define REDIS_CMD_REPLY     254
#define REDIS_CMD_UNKNOWN   255

// ICMP Types
#define ICMP_ECHOREPLY      0
#define ICMP_DEST_UNREACH   3
#define ICMP_SOURCE_QUENCH  4
#define ICMP_REDIRECT       5
#define ICMP_ECHO           8
#define ICMP_TIME_EXCEEDED  11
#define ICMP_PARAMETERPROB  12
#define ICMP_TIMESTAMP      13
#define ICMP_TIMESTAMPREPLY 14
#define ICMP_INFO_REQUEST   15
#define ICMP_INFO_REPLY     16
#define ICMP_ADDRESS        17
#define ICMP_ADDRESSREPLY   18

// DNS Constants
#define DNS_PORT 53
#define MAX_DNS_NAME_LENGTH 32

// Buffer sizes
#define MAX_PAYLOAD 256
#define MAX_REDIS_PAYLOAD 128
#define LOAD_STEP 32
#define MAX_ATTEMPTS 8
#define MAX_HTTP_METHOD_LENGTH 8
#define MAX_HTTP_URI_LENGTH 64
#define MAX_HTTP_STATUS_LENGTH 16
#define MAX_KAFKA_CLIENT_ID_LENGTH 8
#define MAX_KAFKA_TOPIC_LENGTH 16

// 루프 상수 정의
#define DNS_NAME_PARSE_LOOP_SIZE 32
#define REDIS_COMMAND_SEARCH_START 7
#define REDIS_COMMAND_SEARCH_END 20
#define PAYLOAD_COPY_LOOP_SIZE 256
#define HTTP_URI_PARSE_LOOP_SIZE 64

// 구조체 크기 상수 정의
#define BASE_EVENT_SIZE 60
#define HTTP_PAYLOAD_SIZE MAX_PAYLOAD
#define DNS_QUERY_NAME_SIZE MAX_DNS_NAME_LENGTH
#define KAFKA_CLIENT_ID_SIZE MAX_KAFKA_CLIENT_ID_LENGTH
#define KAFKA_TOPIC_SIZE MAX_KAFKA_TOPIC_LENGTH

// Ring Buffer 크기 상수 정의
#define HTTP_RINGBUF_SIZE (1 << 18)
#define HTTP2_RINGBUF_SIZE (1 << 18)
#define DNS_RINGBUF_SIZE (1 << 17)
#define REDIS_RINGBUF_SIZE (1 << 17)
#define ICMP_RINGBUF_SIZE (1 << 16)
#define KAFKA_RINGBUF_SIZE (1 << 17)

// 헤더 크기 상수 정의
#define MIN_IP_HEADER_SIZE 20
#define MAX_IP_HEADER_SIZE 60
#define MIN_TCP_HEADER_SIZE 20
#define MAX_TCP_HEADER_SIZE 60
#define UDP_HEADER_SIZE 8
#define ICMP_HEADER_SIZE 8
#define DNS_HEADER_SIZE 12

// 프로토콜 검증 상수
#define KAFKA_MAX_MESSAGE_SIZE (1024*1024)
#define KAFKA_MAX_API_KEY 67
#define KAFKA_MAX_API_VERSION 15
#define HTTP2_MAX_FRAME_LENGTH 16384

// 페이로드 로딩 상수
#define PAYLOAD_LOAD_MIN_SIZE 64

// 간소화된 공통 기본 구조체
struct base_event {
    __be32 saddr;
    __be32 daddr;
    __u8 ip_tos;
    __u16 ip_total_len;
    __u16 ip_id;
    __u16 ip_frag_off;
    __u8 ip_ttl;
    __u8 ip_protocol;
    __u16 ip_check;
    __u16 sport;
    __u16 dport;
    __u32 seq;
    __u32 ack_seq;
    __u8 tcp_flags;
    __u16 window;
    __u16 tcp_check;
    __u16 udp_len;
    __u16 udp_check;
    __u64 timestamp_ns;
    __u16 payload_size;
};

// 간소화된 HTTP 전용 구조체
struct http_event {
    struct base_event base;
    __u8 http_method[MAX_HTTP_METHOD_LENGTH];
    __u8 http_uri[MAX_HTTP_URI_LENGTH];
    __u8 http_status_code[MAX_HTTP_STATUS_LENGTH];
    __u8 is_request; 
};

// 간소화된 HTTP/2 전용 구조체
struct http2_event {
    struct base_event base;
    __u32 http2_frame_length;
    __u8 http2_frame_type;
    __u8 http2_frame_flags;
    __u32 http2_stream_id;
    __u8 payload[HTTP_PAYLOAD_SIZE];
};

// 간소화된 DNS 전용 구조체
struct dns_event {
    struct base_event base;
    __u16 dns_transaction_id;
    __u16 dns_query_type;
    __u8 dns_query_name[DNS_QUERY_NAME_SIZE];
    __u8 dns_response_code;
    __u8 is_query;
};

// 간소화된 Redis 전용 구조체
struct redis_event {
    struct base_event base;
    __u8 redis_command_type;
    __u8 redis_resp_type;
    __u8 redis_payload[MAX_REDIS_PAYLOAD];
};

// 간소화된 ICMP 전용 구조체
struct icmp_event {
    struct base_event base;
    __u16 icmp_id;
    __u16 icmp_seq;
    __u8 icmp_type;
    __u8 icmp_code;
};

// 간소화된 Kafka 전용 구조체
struct kafka_event {
    struct base_event base;
    __u16 kafka_api_key;
    __u16 kafka_api_version;
    __u32 kafka_correlation_id;
    __u8 payload[MAX_PAYLOAD];
};

// 프로토콜별 Ring Buffer 맵
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, HTTP_RINGBUF_SIZE);
} http_queue SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, HTTP2_RINGBUF_SIZE);
} http2_queue SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DNS_RINGBUF_SIZE);
} dns_queue SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, REDIS_RINGBUF_SIZE);
} redis_queue SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, ICMP_RINGBUF_SIZE);
} icmp_queue SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, KAFKA_RINGBUF_SIZE);
} kafka_queue SEC(".maps");

// Per-CPU array map for payload buffer
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[MAX_PAYLOAD]);
} payload_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[MAX_REDIS_PAYLOAD]);
} redis_payload_heap SEC(".maps");

// Kafka request header structure
struct kafka_request_header {
    __u32 message_size;
    __u16 api_key;
    __u16 api_version;
    __u32 correlation_id;
    __u16 client_id_length;
}__attribute__((packed));

// DNS Header Structure
struct dns_hdr {
    __u16 transaction_id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
}__attribute__((packed));

const struct http_event *unused_http __attribute__((unused));
const struct http2_event *unused_http2 __attribute__((unused));
const struct dns_event *unused_dns __attribute__((unused));
const struct redis_event *unused_redis __attribute__((unused));
const struct icmp_event *unused_icmp __attribute__((unused));
const struct kafka_event *unused_kafka __attribute__((unused));

// 간소화된 공통 필드 복사 함수
static __always_inline void fill_base_event_simple(struct base_event *base, 
    __be32 saddr, __be32 daddr, __u8 tos, __u16 total_len, __u16 id, __u16 frag_off, 
    __u8 ttl, __u8 protocol, __u16 check, __u16 sport, __u16 dport, 
    __u64 timestamp, __u16 payload_size) {
    
    base->saddr = saddr;
    base->daddr = daddr;
    base->ip_tos = tos;
    base->ip_total_len = total_len;
    base->ip_id = id;
    base->ip_frag_off = frag_off;
    base->ip_ttl = ttl;
    base->ip_protocol = protocol;
    base->ip_check = check;
    base->sport = sport;
    base->dport = dport;
    base->timestamp_ns = timestamp;
    base->payload_size = payload_size;
    
    // TCP/UDP 필드는 별도로 설정
    base->seq = 0;
    base->ack_seq = 0;
    base->tcp_flags = 0;
    base->window = 0;
    base->tcp_check = 0;
    base->udp_len = 0;
    base->udp_check = 0;
}

// 수정된 Kafka 프로토콜 감지 함수
static __always_inline __u8 detect_kafka_protocol(__u8 *payload, __u16 size) {
    if (size < 8) return 0;
    
    __u32 msg_size = __bpf_ntohl(*((__u32 *)payload));
    
    // 메시지 크기 1차 검증
    if (msg_size < 4 || msg_size > KAFKA_MAX_MESSAGE_SIZE) {
        return 0;
    }
    
    // if (size >= 14) {
    //     // 완전한 Kafka 헤더 검증
    //     __u16 api_key = __bpf_ntohs(*((__u16 *)(payload + 4)));
    //     __u16 api_version = __bpf_ntohs(*((__u16 *)(payload + 6)));
        
    //     if (api_key <= KAFKA_MAX_API_KEY && api_version <= KAFKA_MAX_API_VERSION) {
    //         return 1;
    //     }
    // } else if (size >= 8) {
    //     // 짧은 패킷은 메시지 크기만으로 판단
    //     return 1;
    // }
    
    return 1;
}



// Redis 프로토콜 감지 함수 (별도 함수)
static __always_inline __u8 detect_redis_protocol(__u8 *payload, __u16 size) {
    if (size < 3) return 0;
    
    if (payload[0] == '*') {
        // Array: 반드시 숫자가 따라와야 함
        if (size >= 2 && payload[1] >= '1' && payload[1] <= '9') {
            // 추가 검증: 3번째 문자가 \r 또는 \n이어야 함
            if (size >= 3 && (payload[2] == '\r' || payload[2] == '\n')) {
                return 1;
            }
        }
    } else if (payload[0] == '+' || payload[0] == '-') {
        // Simple String/Error: ASCII 문자여야 함
        if (size >= 2 && payload[1] >= 32 && payload[1] <= 126) {
            // \r\n으로 끝나는지 확인
            for (int i = 1; i < size - 1; i++) {
                if (payload[i] == '\r' && payload[i+1] == '\n') {
                    return 1;
                }
            }
        }
    } else if (payload[0] == ':') {
        // Integer: 숫자 또는 -여야 함
        if (size >= 2 && ((payload[1] >= '0' && payload[1] <= '9') || payload[1] == '-')) {
            return 1;
        }
    } else if (payload[0] == '$') {
        // Bulk String: 숫자가 따라와야 함
        if (size >= 2 && ((payload[1] >= '0' && payload[1] <= '9') || payload[1] == '-')) {
            return 1;
        }
    }

    return 0;
}

// 완전한 Redis command detection (모든 명령어 포함)
static __always_inline __u8 detect_redis_command(__u8 *payload, int size) {
    if (size < 10) return REDIS_CMD_UNKNOWN;
    if (payload[0] != '*') return REDIS_CMD_REPLY;
    
    #pragma unroll
    for (int i = REDIS_COMMAND_SEARCH_START; i <= REDIS_COMMAND_SEARCH_END; i++) {
        if (i + 6 >= size) break;
        
        // ZRANGE command detection (6 chars) - longest command first
        if (i + 5 < size) {
            if ((payload[i] == 'z' && payload[i+1] == 'r' && payload[i+2] == 'a' && 
                 payload[i+3] == 'n' && payload[i+4] == 'g' && payload[i+5] == 'e') ||
                (payload[i] == 'Z' && payload[i+1] == 'R' && payload[i+2] == 'A' && 
                 payload[i+3] == 'N' && payload[i+4] == 'G' && payload[i+5] == 'E')) {
                return REDIS_CMD_ZRANGE;
            }
        }
        
        // SADD command detection (4 chars) - check before SET to avoid collision
        if (i + 3 < size) {
            if ((payload[i] == 's' && payload[i+1] == 'a' && payload[i+2] == 'd' && payload[i+3] == 'd') ||
                (payload[i] == 'S' && payload[i+1] == 'A' && payload[i+2] == 'D' && payload[i+3] == 'D')) {
                return REDIS_CMD_SADD;
            }
        }
        
        // ZADD command detection (4 chars)
        if (i + 3 < size) {
            if ((payload[i] == 'z' && payload[i+1] == 'a' && payload[i+2] == 'd' && payload[i+3] == 'd') ||
                (payload[i] == 'Z' && payload[i+1] == 'A' && payload[i+2] == 'D' && payload[i+3] == 'D')) {
                return REDIS_CMD_ZADD;
            }
        }
        
        // HSET command detection (4 chars)
        if (i + 3 < size) {
            if ((payload[i] == 'h' && payload[i+1] == 's' && payload[i+2] == 'e' && payload[i+3] == 't') ||
                (payload[i] == 'H' && payload[i+1] == 'S' && payload[i+2] == 'E' && payload[i+3] == 'T')) {
                return REDIS_CMD_HSET;
            }
        }
        
        // HGET command detection (4 chars)
        if (i + 3 < size) {
            if ((payload[i] == 'h' && payload[i+1] == 'g' && payload[i+2] == 'e' && payload[i+3] == 't') ||
                (payload[i] == 'H' && payload[i+1] == 'G' && payload[i+2] == 'E' && payload[i+3] == 'T')) {
                return REDIS_CMD_HGET;
            }
        }
        
        // PING command detection (4 chars)
        if (i + 3 < size) {
            if ((payload[i] == 'p' && payload[i+1] == 'i' && payload[i+2] == 'n' && payload[i+3] == 'g') ||
                (payload[i] == 'P' && payload[i+1] == 'I' && payload[i+2] == 'N' && payload[i+3] == 'G')) {
                return REDIS_CMD_PING;
            }
        }
        
        // INFO command detection (4 chars)
        if (i + 3 < size) {
            if ((payload[i] == 'i' && payload[i+1] == 'n' && payload[i+2] == 'f' && payload[i+3] == 'o') ||
                (payload[i] == 'I' && payload[i+1] == 'N' && payload[i+2] == 'F' && payload[i+3] == 'O')) {
                return REDIS_CMD_INFO;
            }
        }
        
        // GET command detection (3 chars)
        if (i + 2 < size) {
            if ((payload[i] == 'g' && payload[i+1] == 'e' && payload[i+2] == 't') ||
                (payload[i] == 'G' && payload[i+1] == 'E' && payload[i+2] == 'T')) {
                return REDIS_CMD_GET;
            }
        }
        
        // SET command detection (3 chars) - check last to avoid SADD collision
        if (i + 2 < size) {
            if ((payload[i] == 's' && payload[i+1] == 'e' && payload[i+2] == 't') ||
                (payload[i] == 'S' && payload[i+1] == 'E' && payload[i+2] == 'T')) {
                return REDIS_CMD_SET;
            }
        }
    }
    
    return REDIS_CMD_UNKNOWN;
}

// HTTP method detection (기존 로직 유지)
static __always_inline __u8 detect_http_method(__u8 *payload, __u8 *method_buf, __u8 *uri_buf) {
    // Initialize buffers
    #pragma unroll
    for (int i = 0; i < MAX_HTTP_METHOD_LENGTH; i++) {
        method_buf[i] = 0;
    }
    #pragma unroll
    for (int i = 0; i < MAX_HTTP_URI_LENGTH; i++) {
        uri_buf[i] = 0;
    }
    
    __u8 method_len = 0;
    
    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') {
        method_buf[0] = 'G'; method_buf[1] = 'E'; method_buf[2] = 'T';
        method_len = 3;
    } else if (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T' && payload[4] == ' ') {
        method_buf[0] = 'P'; method_buf[1] = 'O'; method_buf[2] = 'S'; method_buf[3] = 'T';
        method_len = 4;
    } else if (payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T' && payload[3] == ' ') {
        method_buf[0] = 'P'; method_buf[1] = 'U'; method_buf[2] = 'T';
        method_len = 3;
    } else if (payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E' && 
               payload[4] == 'T' && payload[5] == 'E' && payload[6] == ' ') {
        method_buf[0] = 'D'; method_buf[1] = 'E'; method_buf[2] = 'L'; method_buf[3] = 'E';
        method_buf[4] = 'T'; method_buf[5] = 'E';
        method_len = 6;
    } else if (payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D' && payload[4] == ' ') {
        method_buf[0] = 'H'; method_buf[1] = 'E'; method_buf[2] = 'A'; method_buf[3] = 'D';
        method_len = 4;
    } else if (payload[0] == 'O' && payload[1] == 'P' && payload[2] == 'T' && payload[3] == 'I' && 
               payload[4] == 'O' && payload[5] == 'N' && payload[6] == 'S' && payload[7] == ' ') {
        method_buf[0] = 'O'; method_buf[1] = 'P'; method_buf[2] = 'T'; method_buf[3] = 'I';
        method_buf[4] = 'O'; method_buf[5] = 'N'; method_buf[6] = 'S';
        method_len = 7;
    } else if (payload[0] == 'P' && payload[1] == 'A' && payload[2] == 'T' && payload[3] == 'C' && payload[4] == 'H' && payload[5] == ' ') {
        method_buf[0] = 'P'; method_buf[1] = 'A'; method_buf[2] = 'T'; method_buf[3] = 'C'; method_buf[4] = 'H';
        method_len = 5;
    } else {
        return 0;
    }
    
    __u8 uri_start = method_len + 1;
    __u8 uri_len = 0;
    
    #pragma unroll
    for (int i = uri_start; i < MAX_PAYLOAD && uri_len < MAX_HTTP_URI_LENGTH - 1; i++) {
        if (payload[i] == ' ' || payload[i] == '\r' || payload[i] == '\n') {
            break;
        }
        uri_buf[uri_len] = payload[i];
        uri_len++;
    }
    
    return 1;
}

static __always_inline __u8 detect_http_response(__u8 *payload, __u8 *status_buf) {
    #pragma unroll
    for (int i = 0; i < MAX_HTTP_STATUS_LENGTH; i++) {
        status_buf[i] = 0;
    }
    
    if (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P') {
        #pragma unroll
        for (int i = 0; i < 3; i++) {
            status_buf[i] = payload[9 + i];
        }
        return 1;
    }
    return 0;
}

// HTTP/2 프레임 헤더 파싱 함수 (기존 로직 유지)
static __always_inline void parse_http2_frame_header_event(__u8 *payload, struct http2_event *msg) {
    // Frame Length (24비트)
    msg->http2_frame_length = (payload[0] << 16) | (payload[1] << 8) | payload[2];
    
    // Frame Type (8비트)
    msg->http2_frame_type = payload[3];
    
    // Frame Flags (8비트)
    msg->http2_frame_flags = payload[4];
    
    // Stream ID (31비트, 최상위 비트는 예약됨)
    __u32 stream_id_raw = (payload[5] << 24) | (payload[6] << 16) | (payload[7] << 8) | payload[8];
    msg->http2_stream_id = stream_id_raw & 0x7FFFFFFF;
}

// 프로토콜 감지 함수 (기존 로직 완전 유지)
static __always_inline __u8 detect_protocol(__u8 *payload, __u16 size, __u8 ip_proto, __u16 sport, __u16 dport) {
    // 1. IP 프로토콜 번호 최우선 검사
    if (ip_proto == IPPROTO_ICMP) {
        return PROTO_ICMP;
    }
    
    // 2. UDP 프로토콜일 때 DNS만 포트 기반 검사
    if (ip_proto == IPPROTO_UDP) {
        if (sport == DNS_PORT || dport == DNS_PORT) {
            return PROTO_DNS;
        }
        return PROTO_UNKNOWN;
    }
    
    // 3. TCP 프로토콜일 때만 애플리케이션 프로토콜 감지
    if (ip_proto != IPPROTO_TCP) {
        return PROTO_TCP;
    }
    
    if (size < 4) return PROTO_UNKNOWN;
    
    // 4. HTTP/2 Connection Preface 검사 (완전 유지)
    if (size >= 24 && 
        payload[0] == 'P' && payload[1] == 'R' && payload[2] == 'I' && payload[3] == ' ' &&
        payload[4] == '*' && payload[5] == ' ' && 
        payload[6] == 'H' && payload[7] == 'T' && payload[8] == 'T' && payload[9] == 'P' &&
        payload[10] == '/' && payload[11] == '2' && payload[12] == '.' && payload[13] == '0' &&
        payload[14] == '\r' && payload[15] == '\n' &&
        payload[16] == '\r' && payload[17] == '\n' &&
        payload[18] == 'S' && payload[19] == 'M' &&
        payload[20] == '\r' && payload[21] == '\n' &&
        payload[22] == '\r' && payload[23] == '\n') {
        return PROTO_HTTP2;
    }
    
    // 5. HTTP/2 Frame 구조 검사 (완전 유지)
    if (size >= 9) {
        __u32 frame_length = (payload[0] << 16) | (payload[1] << 8) | payload[2];
        __u8 frame_type = payload[3];
        
        if (frame_length <= HTTP2_MAX_FRAME_LENGTH && frame_type <= HTTP2_FRAME_CONTINUATION) {
            return PROTO_HTTP2;
        }
    }
    
    // 6. Redis 패턴 검사 (별도 함수 사용)
    if (detect_redis_protocol(payload, size)) {
        return PROTO_REDIS;
    }
    
    // 7. Kafka 패턴 검사 (별도 함수 사용)
    if (detect_kafka_protocol(payload, size)) {
        return PROTO_KAFKA;
    }
    
    // 8. HTTP/1.x 패턴 검사 (완전 유지)
    if ((payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T') ||
        (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T') ||
        (payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T') ||
        (payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E') ||
        (payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D') ||
        (payload[0] == 'O' && payload[1] == 'P' && payload[2] == 'T' && payload[3] == 'I') ||
        (payload[0] == 'P' && payload[1] == 'A' && payload[2] == 'T' && payload[3] == 'C') ||
        (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P')) {
        return PROTO_HTTP;
    }
    
    return PROTO_TCP;
}

// Safe payload loading (기존 로직 유지)
static __always_inline __u16 load_payload_safe(struct __sk_buff *ctx, __u32 offset, __u8 *payload) {
    __u16 actual_size = 0;
    
    #pragma unroll
    for (int i = 0; i < MAX_ATTEMPTS; i++) {
        __u16 try_size = MAX_PAYLOAD - (i * LOAD_STEP);
        if (try_size < PAYLOAD_LOAD_MIN_SIZE)
            break;
        
        if (bpf_skb_load_bytes(ctx, offset, payload, try_size) >= 0) {
            actual_size = try_size;
            break;
        }
    }
    
    return actual_size;
}

SEC("tc")
int ingress_prog_func(struct __sk_buff *ctx) {
    void *data = (void *)(__u64)ctx->data;
    void *data_end = (void *)(__u64)ctx->data_end;
    
    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    struct ethhdr *ethh = data;
    if ((void *)(ethh + 1) > data_end)
        return TC_ACT_OK;
    
    struct iphdr *iph = (void *)(ethh + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_ICMP && iph->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    
    __u32 ip_hdr_len = (iph->ihl & 0xF) << 2;
    if (ip_hdr_len < MIN_IP_HEADER_SIZE || ip_hdr_len > MAX_IP_HEADER_SIZE)
        return TC_ACT_OK;
    
    __u32 payload_offset = sizeof(struct ethhdr) + ip_hdr_len;
    __u16 total_len = __bpf_ntohs(iph->tot_len);
    
    __u16 sport = 0, dport = 0;
    
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)(iph + 1);
        if ((void *)(tcph + 1) > data_end)
            return TC_ACT_OK;
        
        __u32 tcp_hdr_len = (tcph->doff & 0xF) << 2;
        if (tcp_hdr_len < MIN_TCP_HEADER_SIZE || tcp_hdr_len > MAX_TCP_HEADER_SIZE)
            return TC_ACT_OK;
        
        sport = __bpf_ntohs(tcph->source);
        dport = __bpf_ntohs(tcph->dest);
        payload_offset += tcp_hdr_len;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)(iph + 1);
        if ((void *)(udph + 1) > data_end)
            return TC_ACT_OK;
        
        sport = __bpf_ntohs(udph->source);
        dport = __bpf_ntohs(udph->dest);
        payload_offset += UDP_HEADER_SIZE;
    } else if (iph->protocol == IPPROTO_ICMP) {
        payload_offset += ICMP_HEADER_SIZE;
    }

    if (sport == 5317 || dport == 5317) {
        return TC_ACT_OK;
    }
    
    if (payload_offset >= total_len)
        return TC_ACT_OK;
    
    __u16 payload_size = total_len - payload_offset;
    if (payload_size == 0 && iph->protocol == IPPROTO_TCP)
        return TC_ACT_OK;
    
    __u32 key = 0;
    __u8 *payload = bpf_map_lookup_elem(&payload_heap, &key);
    if (!payload)
        return TC_ACT_OK;
    
    __u16 actual_size = 0;
    if (payload_size > 0) {
        actual_size = load_payload_safe(ctx, payload_offset, payload);
    }
    
    __u8 proto_type = detect_protocol(payload, actual_size, iph->protocol, sport, dport);
    
    if (iph->protocol == IPPROTO_ICMP) {
        proto_type = PROTO_ICMP;
    }
    
    if (proto_type == PROTO_UNKNOWN || proto_type == PROTO_TCP) {
        return TC_ACT_OK;
    }
    
    __u64 timestamp = bpf_ktime_get_ns();
    
    if (proto_type == PROTO_DNS) {
        struct dns_event *dns_msg = bpf_ringbuf_reserve(&dns_queue, sizeof(*dns_msg), 0);
        if (!dns_msg) return TC_ACT_OK;
        
        fill_base_event_simple(&dns_msg->base, 
            iph->saddr, iph->daddr, iph->tos, __bpf_ntohs(iph->tot_len),
            __bpf_ntohs(iph->id), __bpf_ntohs(iph->frag_off), iph->ttl,
            iph->protocol, __bpf_ntohs(iph->check), sport, dport,
            timestamp, actual_size);
        
        struct udphdr *udph = (void *)(iph + 1);
        if ((void *)(udph + 1) <= data_end) {
            dns_msg->base.udp_len = __bpf_ntohs(udph->len);
            dns_msg->base.udp_check = __bpf_ntohs(udph->check);
        }
        
        struct dns_hdr *dnsh = (void *)(udph + 1);
        if ((void *)(dnsh + 1) <= data_end) {
            dns_msg->dns_transaction_id = __bpf_ntohs(dnsh->transaction_id);
            __u16 flags = __bpf_ntohs(dnsh->flags);
            dns_msg->is_query = ((flags >> 15) & 0x1) == 0 ? 1 : 0;
            dns_msg->dns_response_code = flags & 0xF;
            
            #pragma unroll
            for (int i = 0; i < DNS_QUERY_NAME_SIZE; i++) {
                dns_msg->dns_query_name[i] = 0;
            }
            
            if (__bpf_ntohs(dnsh->qdcount) > 0) {
                __u8 *cursor = (__u8 *)(dnsh + 1);
                __u8 namepos = 0;
                
                #pragma unroll
                for (int i = 0; i < DNS_NAME_PARSE_LOOP_SIZE; i++) {
                    if (cursor + 1 > (__u8 *)data_end) {
                        break;
                    }
                    
                    if (*cursor == 0) {
                        if (cursor + 3 <= (__u8 *)data_end) {
                            dns_msg->dns_query_type = __bpf_ntohs(*((__u16 *)(cursor + 1)));
                        }
                        break;
                    }
                    
                    if (namepos < DNS_QUERY_NAME_SIZE - 1) {
                        dns_msg->dns_query_name[namepos] = *cursor;
                        namepos++;
                    }
                    cursor++;
                }
            }
        }
        
        bpf_ringbuf_submit(dns_msg, 0);
    } else if (proto_type == PROTO_HTTP) {
        struct http_event *http_msg = bpf_ringbuf_reserve(&http_queue, sizeof(*http_msg), 0);
        if (!http_msg) return TC_ACT_OK;
        
        fill_base_event_simple(&http_msg->base, 
            iph->saddr, iph->daddr, iph->tos, __bpf_ntohs(iph->tot_len),
            __bpf_ntohs(iph->id), __bpf_ntohs(iph->frag_off), iph->ttl,
            iph->protocol, __bpf_ntohs(iph->check), sport, dport,
            timestamp, actual_size);
        
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(iph + 1);
            if ((void *)tcph + MIN_TCP_HEADER_SIZE <= data_end) {
                http_msg->base.seq = __bpf_ntohl(tcph->seq);
                http_msg->base.ack_seq = __bpf_ntohl(tcph->ack_seq);
                http_msg->base.tcp_flags = *(((__u8 *)tcph) + 13);
                http_msg->base.window = __bpf_ntohs(tcph->window);
                http_msg->base.tcp_check = __bpf_ntohs(tcph->check);
            }
        }
        
        if (detect_http_method(payload, http_msg->http_method, http_msg->http_uri)) {
            http_msg->is_request = 1;
        } else if (detect_http_response(payload, http_msg->http_status_code)) {
            http_msg->is_request = 0;
        }
        
        bpf_ringbuf_submit(http_msg, 0);
        
    } else if (proto_type == PROTO_HTTP2) {
        struct http2_event *http2_msg = bpf_ringbuf_reserve(&http2_queue, sizeof(*http2_msg), 0);
        if (!http2_msg) return TC_ACT_OK;
        
        fill_base_event_simple(&http2_msg->base, 
            iph->saddr, iph->daddr, iph->tos, __bpf_ntohs(iph->tot_len),
            __bpf_ntohs(iph->id), __bpf_ntohs(iph->frag_off), iph->ttl,
            iph->protocol, __bpf_ntohs(iph->check), sport, dport,
            timestamp, actual_size);
        
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(iph + 1);
            if ((void *)tcph + MIN_TCP_HEADER_SIZE <= data_end) {
                http2_msg->base.seq = __bpf_ntohl(tcph->seq);
                http2_msg->base.ack_seq = __bpf_ntohl(tcph->ack_seq);
                http2_msg->base.tcp_flags = *(((__u8 *)tcph) + 13);
                http2_msg->base.window = __bpf_ntohs(tcph->window);
                http2_msg->base.tcp_check = __bpf_ntohs(tcph->check);
            }
        }
        
        if (actual_size >= 9) {
            __u32 frame_offset = 0;
            if (actual_size >= 24 && payload[0] == 'P' && payload[1] == 'R' && payload[2] == 'I') {
                frame_offset = 24;
            }
            
            if (frame_offset + 9 <= actual_size) {
                parse_http2_frame_header_event(payload + frame_offset, http2_msg);
            }
        }
        
        __u16 copy_size = actual_size > HTTP_PAYLOAD_SIZE ? HTTP_PAYLOAD_SIZE : actual_size;
        #pragma unroll
        for (int i = 0; i < PAYLOAD_COPY_LOOP_SIZE; i++) {
            if (i >= copy_size) break;
            http2_msg->payload[i] = payload[i];
        }
        
        bpf_ringbuf_submit(http2_msg, 0);
        
    } else if (proto_type == PROTO_REDIS) {
        struct redis_event *redis_msg = bpf_ringbuf_reserve(&redis_queue, sizeof(*redis_msg), 0);
        if (!redis_msg) return TC_ACT_OK;
        
        fill_base_event_simple(&redis_msg->base, 
            iph->saddr, iph->daddr, iph->tos, __bpf_ntohs(iph->tot_len),
            __bpf_ntohs(iph->id), __bpf_ntohs(iph->frag_off), iph->ttl,
            iph->protocol, __bpf_ntohs(iph->check), sport, dport,
            timestamp, actual_size);
        
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(iph + 1);
            if ((void *)tcph + MIN_TCP_HEADER_SIZE <= data_end) {
                redis_msg->base.seq = __bpf_ntohl(tcph->seq);
                redis_msg->base.ack_seq = __bpf_ntohl(tcph->ack_seq);
                redis_msg->base.tcp_flags = *(((__u8 *)tcph) + 13);
                redis_msg->base.window = __bpf_ntohs(tcph->window);
                redis_msg->base.tcp_check = __bpf_ntohs(tcph->check);
            }
        }
        
        if (actual_size >= 3) {
            redis_msg->redis_resp_type = payload[0];
            redis_msg->redis_command_type = detect_redis_command(payload, actual_size);

            if (redis_msg->redis_command_type == REDIS_CMD_UNKNOWN) {
                bpf_ringbuf_discard(redis_msg, 0);
                return TC_ACT_OK;
            }
            
            __u16 copy_size = actual_size > MAX_REDIS_PAYLOAD ? MAX_REDIS_PAYLOAD : actual_size;
            #pragma unroll
            for (int i = 0; i < MAX_REDIS_PAYLOAD; i++) {
                if (i >= copy_size) break;
                redis_msg->redis_payload[i] = payload[i];
            }
        }
        
        bpf_ringbuf_submit(redis_msg, 0);
        
    } else if (proto_type == PROTO_KAFKA) {
        struct kafka_event *kafka_msg = bpf_ringbuf_reserve(&kafka_queue, sizeof(*kafka_msg), 0);
        if (!kafka_msg) return TC_ACT_OK;
        
        fill_base_event_simple(&kafka_msg->base, 
            iph->saddr, iph->daddr, iph->tos, __bpf_ntohs(iph->tot_len),
            __bpf_ntohs(iph->id), __bpf_ntohs(iph->frag_off), iph->ttl,
            iph->protocol, __bpf_ntohs(iph->check), sport, dport,
            timestamp, actual_size);
        
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(iph + 1);
            if ((void *)tcph + MIN_TCP_HEADER_SIZE <= data_end) {
                kafka_msg->base.seq = __bpf_ntohl(tcph->seq);
                kafka_msg->base.ack_seq = __bpf_ntohl(tcph->ack_seq);
                kafka_msg->base.tcp_flags = *(((__u8 *)tcph) + 13);
                kafka_msg->base.window = __bpf_ntohs(tcph->window);
                kafka_msg->base.tcp_check = __bpf_ntohs(tcph->check);
            }
        }
        
        __u16 payload_length = 0;
        if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 256) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 192) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 128) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 96) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 64) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 60) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 55) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 50) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 45) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 40) >= 0) {
        }
        
        kafka_msg->kafka_api_key = __bpf_ntohs(*((__u16 *)(kafka_msg->payload + 4)));
        kafka_msg->kafka_api_version = __bpf_ntohs(*((__u16 *)(kafka_msg->payload + 6)));
        kafka_msg->kafka_correlation_id = __bpf_ntohl(*((__u32 *)(kafka_msg->payload + 8)));

        
        bpf_ringbuf_submit(kafka_msg, 0);
            
    } else if (proto_type == PROTO_ICMP) {
        struct icmp_event *icmp_msg = bpf_ringbuf_reserve(&icmp_queue, sizeof(*icmp_msg), 0);
        if (!icmp_msg) return TC_ACT_OK;
        
        fill_base_event_simple(&icmp_msg->base, 
            iph->saddr, iph->daddr, iph->tos, __bpf_ntohs(iph->tot_len),
            __bpf_ntohs(iph->id), __bpf_ntohs(iph->frag_off), iph->ttl,
            iph->protocol, __bpf_ntohs(iph->check), 0, 0,
            timestamp, actual_size);
        
        struct icmphdr *icmph = (void*)(iph + 1);
        if ((void *)(icmph + 1) <= data_end) {
            icmp_msg->icmp_type = icmph->type;
            icmp_msg->icmp_code = icmph->code;
            
            if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY) {
                icmp_msg->icmp_id = __bpf_ntohs(icmph->un.echo.id);
                icmp_msg->icmp_seq = __bpf_ntohs(icmph->un.echo.sequence);
            }
        }
        
        bpf_ringbuf_submit(icmp_msg, 0);
    }
    
    return TC_ACT_OK;
}

SEC("tc")
int egress_prog_func(struct __sk_buff *ctx) {
    void *data = (void *)(__u64)ctx->data;
    void *data_end = (void *)(__u64)ctx->data_end;
    
    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    struct ethhdr *ethh = data;
    if ((void *)(ethh + 1) > data_end)
        return TC_ACT_OK;
    
    struct iphdr *iph = (void *)(ethh + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_ICMP && iph->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    
    __u32 ip_hdr_len = (iph->ihl & 0xF) << 2;
    if (ip_hdr_len < MIN_IP_HEADER_SIZE || ip_hdr_len > MAX_IP_HEADER_SIZE)
        return TC_ACT_OK;
    
    __u32 payload_offset = sizeof(struct ethhdr) + ip_hdr_len;
    __u16 total_len = __bpf_ntohs(iph->tot_len);
    
    __u16 sport = 0, dport = 0;
    
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)(iph + 1);
        if ((void *)(tcph + 1) > data_end)
            return TC_ACT_OK;
        
        __u32 tcp_hdr_len = (tcph->doff & 0xF) << 2;
        if (tcp_hdr_len < MIN_TCP_HEADER_SIZE || tcp_hdr_len > MAX_TCP_HEADER_SIZE)
            return TC_ACT_OK;
        
        sport = __bpf_ntohs(tcph->source);
        dport = __bpf_ntohs(tcph->dest);
        payload_offset += tcp_hdr_len;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)(iph + 1);
        if ((void *)(udph + 1) > data_end)
            return TC_ACT_OK;
        
        sport = __bpf_ntohs(udph->source);
        dport = __bpf_ntohs(udph->dest);
        payload_offset += UDP_HEADER_SIZE;
    } else if (iph->protocol == IPPROTO_ICMP) {
        payload_offset += ICMP_HEADER_SIZE;
    }

    if (sport == 5317 || dport == 5317) {
        return TC_ACT_OK;
    }
    
    if (payload_offset >= total_len)
        return TC_ACT_OK;
    
    __u16 payload_size = total_len - payload_offset;
    if (payload_size == 0 && iph->protocol == IPPROTO_TCP)
        return TC_ACT_OK;
    
    __u32 key = 0;
    __u8 *payload = bpf_map_lookup_elem(&payload_heap, &key);
    if (!payload)
        return TC_ACT_OK;
    
    __u16 actual_size = 0;
    if (payload_size > 0) {
        actual_size = load_payload_safe(ctx, payload_offset, payload);
    }
    
    __u8 proto_type = detect_protocol(payload, actual_size, iph->protocol, sport, dport);
    
    if (iph->protocol == IPPROTO_ICMP) {
        proto_type = PROTO_ICMP;
    }
    
    if (proto_type == PROTO_UNKNOWN || proto_type == PROTO_TCP) {
        return TC_ACT_OK;
    }
    
    __u64 timestamp = bpf_ktime_get_ns();
    
    if (proto_type == PROTO_DNS) {
        struct dns_event *dns_msg = bpf_ringbuf_reserve(&dns_queue, sizeof(*dns_msg), 0);
        if (!dns_msg) return TC_ACT_OK;
        
        fill_base_event_simple(&dns_msg->base, 
            iph->saddr, iph->daddr, iph->tos, __bpf_ntohs(iph->tot_len),
            __bpf_ntohs(iph->id), __bpf_ntohs(iph->frag_off), iph->ttl,
            iph->protocol, __bpf_ntohs(iph->check), sport, dport,
            timestamp, actual_size);
        
        struct udphdr *udph = (void *)(iph + 1);
        if ((void *)(udph + 1) <= data_end) {
            dns_msg->base.udp_len = __bpf_ntohs(udph->len);
            dns_msg->base.udp_check = __bpf_ntohs(udph->check);
        }
        
        struct dns_hdr *dnsh = (void *)(udph + 1);
        if ((void *)(dnsh + 1) <= data_end) {
            dns_msg->dns_transaction_id = __bpf_ntohs(dnsh->transaction_id);
            __u16 flags = __bpf_ntohs(dnsh->flags);
            dns_msg->is_query = ((flags >> 15) & 0x1) == 0 ? 1 : 0;
            dns_msg->dns_response_code = flags & 0xF;
            
            #pragma unroll
            for (int i = 0; i < DNS_QUERY_NAME_SIZE; i++) {
                dns_msg->dns_query_name[i] = 0;
            }
            
            if (__bpf_ntohs(dnsh->qdcount) > 0) {
                __u8 *cursor = (__u8 *)(dnsh + 1);
                __u8 namepos = 0;
                
                #pragma unroll
                for (int i = 0; i < DNS_NAME_PARSE_LOOP_SIZE; i++) {
                    if (cursor + 1 > (__u8 *)data_end) {
                        break;
                    }
                    
                    if (*cursor == 0) {
                        if (cursor + 3 <= (__u8 *)data_end) {
                            dns_msg->dns_query_type = __bpf_ntohs(*((__u16 *)(cursor + 1)));
                        }
                        break;
                    }
                    
                    if (namepos < DNS_QUERY_NAME_SIZE - 1) {
                        dns_msg->dns_query_name[namepos] = *cursor;
                        namepos++;
                    }
                    cursor++;
                }
            }
        }
        
        bpf_ringbuf_submit(dns_msg, 0);
    } else if (proto_type == PROTO_HTTP) {
        struct http_event *http_msg = bpf_ringbuf_reserve(&http_queue, sizeof(*http_msg), 0);
        if (!http_msg) return TC_ACT_OK;
        
        fill_base_event_simple(&http_msg->base, 
            iph->saddr, iph->daddr, iph->tos, __bpf_ntohs(iph->tot_len),
            __bpf_ntohs(iph->id), __bpf_ntohs(iph->frag_off), iph->ttl,
            iph->protocol, __bpf_ntohs(iph->check), sport, dport,
            timestamp, actual_size);
        
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(iph + 1);
            if ((void *)tcph + MIN_TCP_HEADER_SIZE <= data_end) {
                http_msg->base.seq = __bpf_ntohl(tcph->seq);
                http_msg->base.ack_seq = __bpf_ntohl(tcph->ack_seq);
                http_msg->base.tcp_flags = *(((__u8 *)tcph) + 13);
                http_msg->base.window = __bpf_ntohs(tcph->window);
                http_msg->base.tcp_check = __bpf_ntohs(tcph->check);
            }
        }
        
        if (detect_http_method(payload, http_msg->http_method, http_msg->http_uri)) {
            http_msg->is_request = 1;
        } else if (detect_http_response(payload, http_msg->http_status_code)) {
            http_msg->is_request = 0;
        }
        
        bpf_ringbuf_submit(http_msg, 0);
        
    } else if (proto_type == PROTO_HTTP2) {
        struct http2_event *http2_msg = bpf_ringbuf_reserve(&http2_queue, sizeof(*http2_msg), 0);
        if (!http2_msg) return TC_ACT_OK;
        
        fill_base_event_simple(&http2_msg->base, 
            iph->saddr, iph->daddr, iph->tos, __bpf_ntohs(iph->tot_len),
            __bpf_ntohs(iph->id), __bpf_ntohs(iph->frag_off), iph->ttl,
            iph->protocol, __bpf_ntohs(iph->check), sport, dport,
            timestamp, actual_size);
        
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(iph + 1);
            if ((void *)tcph + MIN_TCP_HEADER_SIZE <= data_end) {
                http2_msg->base.seq = __bpf_ntohl(tcph->seq);
                http2_msg->base.ack_seq = __bpf_ntohl(tcph->ack_seq);
                http2_msg->base.tcp_flags = *(((__u8 *)tcph) + 13);
                http2_msg->base.window = __bpf_ntohs(tcph->window);
                http2_msg->base.tcp_check = __bpf_ntohs(tcph->check);
            }
        }
        
        if (actual_size >= 9) {
            __u32 frame_offset = 0;
            if (actual_size >= 24 && payload[0] == 'P' && payload[1] == 'R' && payload[2] == 'I') {
                frame_offset = 24;
            }
            
            if (frame_offset + 9 <= actual_size) {
                parse_http2_frame_header_event(payload + frame_offset, http2_msg);
            }
        }
        
        __u16 copy_size = actual_size > HTTP_PAYLOAD_SIZE ? HTTP_PAYLOAD_SIZE : actual_size;
        #pragma unroll
        for (int i = 0; i < PAYLOAD_COPY_LOOP_SIZE; i++) {
            if (i >= copy_size) break;
            http2_msg->payload[i] = payload[i];
        }
        
        bpf_ringbuf_submit(http2_msg, 0);
        
    } else if (proto_type == PROTO_REDIS) {
        struct redis_event *redis_msg = bpf_ringbuf_reserve(&redis_queue, sizeof(*redis_msg), 0);
        if (!redis_msg) return TC_ACT_OK;
        
        fill_base_event_simple(&redis_msg->base, 
            iph->saddr, iph->daddr, iph->tos, __bpf_ntohs(iph->tot_len),
            __bpf_ntohs(iph->id), __bpf_ntohs(iph->frag_off), iph->ttl,
            iph->protocol, __bpf_ntohs(iph->check), sport, dport,
            timestamp, actual_size);
        
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(iph + 1);
            if ((void *)tcph + MIN_TCP_HEADER_SIZE <= data_end) {
                redis_msg->base.seq = __bpf_ntohl(tcph->seq);
                redis_msg->base.ack_seq = __bpf_ntohl(tcph->ack_seq);
                redis_msg->base.tcp_flags = *(((__u8 *)tcph) + 13);
                redis_msg->base.window = __bpf_ntohs(tcph->window);
                redis_msg->base.tcp_check = __bpf_ntohs(tcph->check);
            }
        }
        
        if (actual_size >= 3) {
            redis_msg->redis_resp_type = payload[0];
            redis_msg->redis_command_type = detect_redis_command(payload, actual_size);

            if (redis_msg->redis_command_type == REDIS_CMD_UNKNOWN) {
                bpf_ringbuf_discard(redis_msg, 0);
                return TC_ACT_OK;
            }
            
            __u16 copy_size = actual_size > MAX_REDIS_PAYLOAD ? MAX_REDIS_PAYLOAD : actual_size;
            #pragma unroll
            for (int i = 0; i < MAX_REDIS_PAYLOAD; i++) {
                if (i >= copy_size) break;
                redis_msg->redis_payload[i] = payload[i];
            }
        }
        
        bpf_ringbuf_submit(redis_msg, 0);
        
    } else if (proto_type == PROTO_KAFKA) {
        struct kafka_event *kafka_msg = bpf_ringbuf_reserve(&kafka_queue, sizeof(*kafka_msg), 0);
        if (!kafka_msg) return TC_ACT_OK;
        
        fill_base_event_simple(&kafka_msg->base, 
            iph->saddr, iph->daddr, iph->tos, __bpf_ntohs(iph->tot_len),
            __bpf_ntohs(iph->id), __bpf_ntohs(iph->frag_off), iph->ttl,
            iph->protocol, __bpf_ntohs(iph->check), sport, dport,
            timestamp, actual_size);
        
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(iph + 1);
            if ((void *)tcph + MIN_TCP_HEADER_SIZE <= data_end) {
                kafka_msg->base.seq = __bpf_ntohl(tcph->seq);
                kafka_msg->base.ack_seq = __bpf_ntohl(tcph->ack_seq);
                kafka_msg->base.tcp_flags = *(((__u8 *)tcph) + 13);
                kafka_msg->base.window = __bpf_ntohs(tcph->window);
                kafka_msg->base.tcp_check = __bpf_ntohs(tcph->check);
            }
        }
        
        __u16 payload_length = 0;
        if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 256) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 192) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 128) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 96) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 64) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 60) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 55) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 50) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 45) >= 0) {

        } else if (bpf_skb_load_bytes(ctx, payload_offset, kafka_msg->payload, 40) >= 0) {
        }
        
        kafka_msg->kafka_api_key = __bpf_ntohs(*((__u16 *)(kafka_msg->payload + 4)));
        kafka_msg->kafka_api_version = __bpf_ntohs(*((__u16 *)(kafka_msg->payload + 6)));
        kafka_msg->kafka_correlation_id = __bpf_ntohl(*((__u32 *)(kafka_msg->payload + 8)));

        
        bpf_ringbuf_submit(kafka_msg, 0);
            
    } else if (proto_type == PROTO_ICMP) {
        struct icmp_event *icmp_msg = bpf_ringbuf_reserve(&icmp_queue, sizeof(*icmp_msg), 0);
        if (!icmp_msg) return TC_ACT_OK;
        
        fill_base_event_simple(&icmp_msg->base, 
            iph->saddr, iph->daddr, iph->tos, __bpf_ntohs(iph->tot_len),
            __bpf_ntohs(iph->id), __bpf_ntohs(iph->frag_off), iph->ttl,
            iph->protocol, __bpf_ntohs(iph->check), 0, 0,
            timestamp, actual_size);
        
        struct icmphdr *icmph = (void*)(iph + 1);
        if ((void *)(icmph + 1) <= data_end) {
            icmp_msg->icmp_type = icmph->type;
            icmp_msg->icmp_code = icmph->code;
            
            if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY) {
                icmp_msg->icmp_id = __bpf_ntohs(icmph->un.echo.id);
                icmp_msg->icmp_seq = __bpf_ntohs(icmph->un.echo.sequence);
            }
        }
        
        bpf_ringbuf_submit(icmp_msg, 0);
    }
    
    return TC_ACT_OK;
}
