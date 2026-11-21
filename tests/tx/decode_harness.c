/* Reads lines "KEYSPEC<TAB>HEX" and prints what the sniffer decodes. */
#include "mesh_packet.h"
#include "mesh_decoders.h"
#include "keyset.h"
#include "pki.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fired;

static void cb(const mesh_event_t *ev, void *user)
{
    (void)user;
    g_fired = 1;
    printf("from=%08x to=%08x id=%08x hop_limit=%d hop_start=%d want_ack=%d "
           "relay=%02x dec=%d pki=%d chan=%s port=%u want_resp=%d req=%08x reply=%08x payload=",
           ev->header.from, ev->header.to, ev->header.packet_id,
           ev->hop_limit, ev->hop_start, ev->want_ack, ev->header.relay_node,
           ev->decrypted, ev->pki_encrypted, ev->channel_name[0] ? ev->channel_name : "-", ev->portnum,
           ev->want_response, ev->request_id, ev->reply_id);
    for (size_t i = 0; i < ev->payload_len; ++i) printf("%02x", ev->payload[i]);
    /* what the sniffer's own decoders make of our node info / position / telemetry */
    if (ev->decrypted && ev->portnum == 3) {
        mesh_position_t p;
        if (mesh_decode_position(ev->payload, ev->payload_len, &p))
            printf(" lat=%.7f lon=%.7f alt=%s%d time=%u src=%u prec=%u", p.lat_deg, p.lon_deg,
                   p.have_alt ? "" : "none:", p.altitude_m, p.time, p.location_source, p.precision_bits);
    } else if (ev->decrypted && ev->portnum == 4) {
        mesh_user_t u;
        if (mesh_decode_user(ev->payload, ev->payload_len, &u))
            printf(" uid=%s short=%s hw=%u pubkey=%d", u.id, u.short_name, u.hw_model, u.have_public_key);
    } else if (ev->decrypted && ev->portnum == 67) {
        mesh_telemetry_t t;
        if (mesh_decode_telemetry(ev->payload, ev->payload_len, &t))
            printf(" ttime=%u dev=%d batt=%u volt=%.3f cu=%.3f au=%.3f up=%u", t.time_unix, t.have_device,
                   t.battery_level, t.voltage, t.channel_utilization, t.air_util_tx, t.uptime_seconds);
    }
    printf("\n");
}

int main(void)
{
    char line[4096];
    while (fgets(line, sizeof(line), stdin)) {
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = 0;
        char *hex = tab + 1;
        hex[strcspn(hex, "\r\n")] = 0;
        uint8_t frame[512];
        size_t n = strlen(hex) / 2;
        for (size_t i = 0; i < n; ++i) sscanf(hex + 2 * i, "%2hhx", &frame[i]);
        keyset_t *ks = keyset_create();
        /* "pki:OURPRIVHEX:PEERPUBHEX:OURNODEHEX:PEERNODEHEX" = public-key DM
         * to us; anything else is a keyset csv ("-" = none). */
        if (!strncmp(line, "pki:", 4)) {
            char priv[65], peer[65];
            unsigned own, from;
            if (sscanf(line + 4, "%64[0-9a-f]:%64[0-9a-f]:%x:%x", priv, peer, &own, &from) == 4) {
                char path[] = "/tmp/harness_key_XXXXXX";
                int fd = mkstemp(path);
                uint8_t k[32];
                pki_key_decode(priv, k);
                char b64[45];
                pki_b64_encode(k, b64);
                dprintf(fd, "%s\n", b64);
                close(fd);
                pki_init(path);
                unlink(path);
                pki_set_own_node(own);
                pki_key_decode(peer, k);
                pki_note_peer(from, k);
                mesh_packet_set_pki_decrypt(pki_mesh_hook);
            }
        } else if (strcmp(line, "-")) keyset_parse_csv(ks, line);
        g_fired = 0;
        int rc = mesh_packet_decode(frame, n, ks, cb, NULL);
        if (!g_fired) printf("NO_EVENT rc=%d\n", rc);
        fflush(stdout);
        keyset_destroy(ks);
    }
    return 0;
}
