/*
 * MimiBoot - the RAM mailbox: what the running image leaves for the next boot
 * (format in mimiboot/mb_handoff.h)
 *
 * First thing on a boot, before the decision, the bootloader looks in the
 * handoff buffer of the image it started last (and, should the log not know,
 * of the other slots' images). A mailbox there that was written by that very
 * image (its image_id) and has a good CRC says why it reset (a reason, a
 * message, where it crashed) and maybe what to boot next. It is cleared before
 * anything acts on it, so it is used once, and reading or clearing it writes
 * no flash.
 *
 * Without a mailbox, the reset hardware is all there is to go on: power-on,
 * watchdog, or a soft reset nobody explained. Only ports whose RAM survives a
 * reset (port->retains_ram) look at all.
 */
#include "core/mimiboot.h"
#include <string.h>

#if !MB_FEAT_OS_HOOKS
void mb_mailbox_take(const mb_port_t* p, const mb_bcl_rec_t* log) { (void)p; (void)log; }
bool mb_mailbox_crashed(void) { return false; }
#else

mb_end_t mb_last_end;
mb_control_request_t mb_mailbox_next;
static bool crashed;

// The mailbox in one slot's image's buffer, if that image left one
static bool take_from(const mb_port_t* p, int slot, mb_mailbox_t* m) {
    mb_slot_info_t in;
    mb_checking_slot = (uint8_t)slot;                   // a fault reading it is this slot's flash
    int rc = mb_image_read_header(p, slot, &in);
    mb_checking_slot = MB_SLOT_NONE;
    if (rc != MB_OK || in.fmt != MB_FMT_NATIVE) return false;
    const mb_image_hdr_t* h = &in.hdr;
    if (!h->handoff_addr || h->handoff_size < MB_HANDOFF_V2_SIZE) return false;     // no room for one there
    volatile mb_mailbox_t* ram = p->ram_ptr(h->handoff_addr, sizeof(*m));
    if (!ram || ram->magic != MB_MAILBOX_MAGIC) return false;
    memcpy(m, (const void*)ram, sizeof(*m));
    if (m->image_id != mb_image_id(h)) return false;   // another image's (at the same address): not this one's to take
    ram->magic = 0;                                     // used once, whatever else it holds
    return m->version == MB_MAILBOX_VERSION && m->size == sizeof(*m) &&
           mb_crc32(0, m, offsetof(mb_mailbox_t, crc)) == m->crc && m->end.reason <= MB_END_LOADER;
}

// The image that ran last left it: the log says which. When the log doesn't know
// (a board whose log couldn't be written), every slot's image is asked.
static bool take(const mb_port_t* p, const mb_bcl_rec_t* log, mb_mailbox_t* m) {
    if (!p->ram_ptr || !p->retains_ram) return false;
    if (log->last_slot < p->layout->n_slots) return take_from(p, log->last_slot, m);
    for (int s = 0; s < p->layout->n_slots; s++)
        if (take_from(p, s, m)) return true;
    return false;
}

void mb_mailbox_take(const mb_port_t* p, const mb_bcl_rec_t* log) {
    memset(&mb_last_end, 0, sizeof(mb_last_end));
    memset(&mb_mailbox_next, 0, sizeof(mb_mailbox_next));
    crashed = false;
    uint32_t cause = p->reset_cause ? p->reset_cause() : 0;
    mb_mailbox_t m;
    if (take(p, log, &m)) {
        mb_last_end = m.end;
        mb_last_end.msg[sizeof(mb_last_end.msg) - 1] = 0;
        mb_last_end.flags = MB_ENDF_NOTED;
        crashed = m.end.reason == MB_END_PANIC || m.end.reason == MB_END_FAULT;
        if (MB_FEAT_CONTROL && m.next.version) mb_mailbox_next = m.next;
    } else {
        mb_last_end.reason = (cause & MB_RESET_WATCHDOG) ? MB_END_WATCHDOG
                           : (cause & MB_RESET_POWER)    ? MB_END_POWER_ON
                           : (log->flags & MB_LF_HANDOVER) ? MB_END_LOADER
                                                          : MB_END_UNKNOWN;
    }
    if (crashed || (cause & MB_RESET_WATCHDOG)) mb_last_end.flags |= MB_ENDF_CRASH;
}

bool mb_mailbox_crashed(void) { return crashed; }

#endif /* MB_FEAT_OS_HOOKS */
