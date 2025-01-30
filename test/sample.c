int _gnutls_ciphertext2compressed(gnutls_session_t session,
                                  opaque *compress_data,
                                  int compress_size,
                                  gnutls_datum_t ciphertext, uint8 type)
{
    uint8 MAC[MAX_HASH_SIZE];
    uint16 c_length;
    uint8 pad;
    int length;
    mac_hd_t td;
    uint16 blocksize;
    int ret, i, pad_failed = 0;
    uint8 major, minor;
    gnutls_protocol_t ver;
    int hash_size =
        _gnutls_hash_get_algo_len(session->security_parameters.read_mac_algorithm);

    ver = gnutls_protocol_get_version(session);
    minor = _gnutls_version_get_minor(ver);
    major = _gnutls_version_get_major(ver);

    blocksize = _gnutls_cipher_get_block_size(session->security_parameters.read_bulk_cipher_algorithm);

    /* initialize MAC
     */
    td = mac_init(session->security_parameters.read_mac_algorithm,
                  session->connection_state.read_mac_secret.data,
                  session->connection_state.read_mac_secret.size, ver);

    if (td == GNUTLS_MAC_FAILED && session->security_parameters.read_mac_algorithm !=
                                       GNUTLS_MAC_NULL)
    {
        gnutls_assert();
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* actual decryption (inplace)
     */
    switch (_gnutls_cipher_is_block(session->security_parameters.read_bulk_cipher_algorithm))
    {
    case CIPHER_STREAM:
        if ((ret = _gnutls_cipher_decrypt(session->connection_state.read_cipher_state,
                                          ciphertext.data,
                                          ciphertext.size)) < 0)
        {
            gnutls_assert();
            return ret;
        }

        length = ciphertext.size - hash_size;

        break;
    case CIPHER_BLOCK:
        if ((ciphertext.size < blocksize) || (ciphertext.size % blocksize != 0))
        {
            gnutls_assert();
            return GNUTLS_E_DECRYPTION_FAILED;
        }

        if ((ret = _gnutls_cipher_decrypt(session->connection_state.read_cipher_state,
                                          ciphertext.data,
                                          ciphertext.size)) < 0)
        {
            gnutls_assert();
            return ret;
        }

        /* ignore the IV in TLS 1.1.
         */
        if (session->security_parameters.version >= GNUTLS_TLS1_1)
        {
            ciphertext.size -= blocksize;
            ciphertext.data += blocksize;

            if (ciphertext.size == 0)
            {
                gnutls_assert();
                return GNUTLS_E_DECRYPTION_FAILED;
            }
        }

        pad = ciphertext.data[ciphertext.size - 1] + 1; /* pad */

        length = ciphertext.size - hash_size - pad;

        if (pad > ciphertext.size - hash_size)
        {
            gnutls_assert();
            /* We do not fail here. We check below for the
             * the pad_failed. If zero means success.
             */
            pad_failed = GNUTLS_E_DECRYPTION_FAILED;
        }

        /* Check the pading bytes (TLS 1.x)
         */
        if (ver >= GNUTLS_TLS1)
            for (i = 2; i < pad; i++)
            {
                if (ciphertext.data[ciphertext.size - i] !=
                    ciphertext.data[ciphertext.size - 1])
                    pad_failed = GNUTLS_E_DECRYPTION_FAILED;
            }

        break;
    default:
        gnutls_assert();
        return GNUTLS_E_INTERNAL_ERROR;
    }

    if (length < 0)
        length = 0;
    c_length = _gnutls_conv_uint16((uint16)length);

    /* Pass the type, version, length and compressed through
     * MAC.
     */
    if (td != GNUTLS_MAC_FAILED)
    {
        _gnutls_hmac(td,
                     UINT64DATA(session->connection_state.read_sequence_number), 8);

        _gnutls_hmac(td, &type, 1);
        if (ver >= GNUTLS_TLS1)
        { /* TLS 1.x */
            _gnutls_hmac(td, &major, 1);
            _gnutls_hmac(td, &minor, 1);
        }
        _gnutls_hmac(td, &c_length, 2);

        if (length > 0)
            _gnutls_hmac(td, ciphertext.data, length);

        mac_deinit(td, MAC, ver);
    }

    /* This one was introduced to avoid a timing attack against the TLS
     * 1.0 protocol.
     */
    if (pad_failed != 0)
        return pad_failed;

    /* HMAC was not the same.
     */
    if (memcmp(MAC, &ciphertext.data[length], hash_size) != 0)
    {
        gnutls_assert();
        return GNUTLS_E_DECRYPTION_FAILED;
    }

    /* copy the decrypted stuff to compress_data.
     */
    if (compress_size < length)
    {
        gnutls_assert();
        return GNUTLS_E_INTERNAL_ERROR;
    }
    memcpy(compress_data, ciphertext.data, length);

    return length;
}
static char *make_filename_safe(const char *filename TSRMLS_DC)
{
    if (*filename && strncmp(filename, "" : memory : "", sizeof("" : memory : "") - 1))
    {
        char *fullpath = expand_filepath(filename, NULL TSRMLS_CC);

        if (!fullpath)
        {
            return NULL;
        }

        if (PG(safe_mode) && (!php_checkuid(fullpath, NULL, CHECKUID_CHECK_FILE_AND_DIR)))
        {
            efree(fullpath);
            return NULL;
        }

        if (php_check_open_basedir(fullpath TSRMLS_CC))
        {
            efree(fullpath);
            return NULL;
        }
        return fullpath;
    }
    return estrdup(filename);
}

unpack_Z_stream(int fd_in, int fd_out)
{
    IF_DESKTOP(long long total_written = 0;)
    IF_DESKTOP(long long)
    int retval = -1;
    unsigned char *stackp;
    long code;
    int finchar;
    long oldcode;
    long incode;
    int inbits;
    int posbits;
    int outpos;
    int insize;
    int bitmask;
    long free_ent;
    long maxcode;
    long maxmaxcode;
    int n_bits;
    int rsize = 0;
    unsigned char *inbuf;  /* were eating insane amounts of stack - */
    unsigned char *outbuf; /* bad for some embedded targets */
    unsigned char *htab;
    unsigned short *codetab;

    /* Hmm, these were statics - why?! */
    /* user settable max # bits/code */
    int maxbits; /* = BITS; */
    /* block compress mode -C compatible with 2.0 */
    int block_mode; /* = BLOCK_MODE; */

    inbuf = xzalloc(IBUFSIZ + 64);
    outbuf = xzalloc(OBUFSIZ + 2048);
    htab = xzalloc(HSIZE); /* wsn't zeroed out before, maybe can xmalloc? */
    codetab = xzalloc(HSIZE * sizeof(codetab[0]));

    insize = 0;

    /* xread isn't good here, we have to return - caller may want
     * to do some cleanup (e.g. delete inHigh unpacked file etc) */
    if (full_read(fd_in, inbuf, 1) != 1)
    {
        bb_error_msg("" short read "");
        goto err;
    }

    maxbits = inbuf[0] & BIT_MASK;
    block_mode = inbuf[0] & BLOCK_MODE;
    maxmaxcode = MAXCODE(maxbits);

    if (maxbits > BITS)
    {
        bb_error_msg("" compressed with % d bits, can only handle "" BITS_STR "" bits "", maxbits);
        goto err;
    }

    n_bits = INIT_BITS;
    maxcode = MAXCODE(INIT_BITS) - 1;
    bitmask = (1 << INIT_BITS) - 1;
    oldcode = -1;
    finchar = 0;
    outpos = 0;
    posbits = 0 << 3;

    free_ent = ((block_mode) ? FIRST : 256);

    /* As above, initialize the first 256 entries in the table. */
    /*clear_tab_prefixof(); - done by xzalloc */

    for (code = 255; code >= 0; --code)
    {
        tab_suffixof(code) = (unsigned char)code;
    }

    do
    {
    resetbuf:
    {
        int i;
        int e;
        int o;

        o = posbits >> 3;
        e = insize - o;

        for (i = 0; i < e; ++i)
            inbuf[i] = inbuf[i + o];

        insize = e;
        posbits = 0;
    }

        if (insize < (int)(IBUFSIZ + 64) - IBUFSIZ)
        {
            rsize = safe_read(fd_in, inbuf + insize, IBUFSIZ);
            // error check??
            insize += rsize;
        }

        inbits = ((rsize > 0) ? (insize - insize % n_bits) << 3 : (insize << 3) - (n_bits - 1));

        while (inbits > posbits)
        {
            if (free_ent > maxcode)
            {
                posbits =
                    ((posbits - 1) +
                     ((n_bits << 3) -
                      (posbits - 1 + (n_bits << 3)) % (n_bits << 3)));
                ++n_bits;
                if (n_bits == maxbits)
                {
                    maxcode = maxmaxcode;
                }
                else
                {
                    maxcode = MAXCODE(n_bits) - 1;
                }
                bitmask = (1 << n_bits) - 1;
                goto resetbuf;
            }
            {
                unsigned char *p = &inbuf[posbits >> 3];

                code = ((((long)(p[0])) | ((long)(p[1]) << 8) |
                         ((long)(p[2]) << 16)) >>
                        (posbits & 0x7)) &
                       bitmask;
            }
            posbits += n_bits;

            if (oldcode == -1)
            {
                oldcode = code;
                finchar = (int)oldcode;
                outbuf[outpos++] = (unsigned char)finchar;
                continue;
            }

            if (code == CLEAR && block_mode)
            {
                clear_tab_prefixof();
                free_ent = FIRST - 1;
                posbits =
                    ((posbits - 1) +
                     ((n_bits << 3) -
                      (posbits - 1 + (n_bits << 3)) % (n_bits << 3)));
                n_bits = INIT_BITS;
                maxcode = MAXCODE(INIT_BITS) - 1;
                bitmask = (1 << INIT_BITS) - 1;
                goto resetbuf;
            }

            incode = code;
            stackp = de_stack;

            /* Special case for KwKwK string. */
            if (code >= free_ent)
            {
                if (code > free_ent)
                {
                    unsigned char *p;

                    posbits -= n_bits;
                    p = &inbuf[posbits >> 3];

                    bb_error_msg("" insize : % d posbits : % d inbuf : % 02X % 02X % 02X % 02X % 02X(% d) "",
                                 insize, posbits, p[-1], p[0], p[1], p[2], p[3],
                                 (posbits & 07));
                    bb_error_msg("" corrupted data "");
                    goto err;
                }

                *--stackp = (unsigned char)finchar;
                code = oldcode;
            }

            /* Generate output characters in reverse order */
            while ((long)code >= (long)256)
            {
                *--stackp = tab_suffixof(code);
                code = tab_prefixof(code);
            }

            finchar = tab_suffixof(code);
            *--stackp = (unsigned char)finchar;

            /* And put them out in forward order */
            {
                int i;

                i = de_stack - stackp;
                if (outpos + i >= OBUFSIZ)
                {
                    do
                    {
                        if (i > OBUFSIZ - outpos)
                        {
                            i = OBUFSIZ - outpos;
                        }

                        if (i > 0)
                        {
                            memcpy(outbuf + outpos, stackp, i);
                            outpos += i;
                        }

                        if (outpos >= OBUFSIZ)
                        {
                            full_write(fd_out, outbuf, outpos);
                            // error check??
                            IF_DESKTOP(total_written += outpos;)
                            outpos = 0;
                        }
                        stackp += i;
                        i = de_stack - stackp;
                    } while (i > 0);
                }
                else
                {
                    memcpy(outbuf + outpos, stackp, i);
                    outpos += i;
                }
            }

            /* Generate the new entry. */
            code = free_ent;
            if (code < maxmaxcode)
            {
                tab_prefixof(code) = (unsigned short)oldcode;
                tab_suffixof(code) = (unsigned char)finchar;
                free_ent = code + 1;
            }

            /* Remember previous code.  */
            oldcode = incode;
        }

    } while (rsize > 0);

    if (outpos > 0)
    {
        full_write(fd_out, outbuf, outpos);
        // error check??
        IF_DESKTOP(total_written += outpos;)
    }

    retval = IF_DESKTOP(total_written) + 0;
err:
    free(inbuf);
    free(outbuf);
    free(htab);
    free(codetab);
    return retval;
}

static void cirrus_do_copy(CirrusVGAState *s, int dst, int src, int w, int h)
{
    int sx, sy;
    int dx, dy;
    int width, height;
    int depth;
    int notify = 0;

    depth = s->get_bpp((VGAState *)s) / 8;
    s->get_resolution((VGAState *)s, &width, &height);

    /* extra x, y */
    sx = (src % (width * depth)) / depth;
    sy = (src / (width * depth));
    dx = (dst % (width * depth)) / depth;
    dy = (dst / (width * depth));

    /* normalize width */
    w /= depth;

    /* if we're doing a backward copy, we have to adjust
       our x/y to be the upper left corner (instead of the lower
       right corner) */
    if (s->cirrus_blt_dstpitch < 0)
    {
        sx -= (s->cirrus_blt_width / depth) - 1;
        dx -= (s->cirrus_blt_width / depth) - 1;
        sy -= s->cirrus_blt_height - 1;
        dy -= s->cirrus_blt_height - 1;
    }

    /* are we in the visible portion of memory? */
    if (sx >= 0 && sy >= 0 && dx >= 0 && dy >= 0 &&
        (sx + w) <= width && (sy + h) <= height &&
        (dx + w) <= width && (dy + h) <= height)
    {
        notify = 1;
    }

    /* make to sure only copy if it's a plain copy ROP */
    if (*s->cirrus_rop != cirrus_bitblt_rop_fwd_src &&
        *s->cirrus_rop != cirrus_bitblt_rop_bkwd_src)
        notify = 0;

    /* we have to flush all pending changes so that the copy
       is generated at the appropriate moment in time */
    if (notify)
        vga_hw_update();

    (*s->cirrus_rop)(s, s->vram_ptr + s->cirrus_blt_dstaddr,
                     s->vram_ptr + s->cirrus_blt_srcaddr,
                     s->cirrus_blt_dstpitch, s->cirrus_blt_srcpitch,
                     s->cirrus_blt_width, s->cirrus_blt_height);

    if (notify)
        s->ds->dpy_copy(s->ds,
                        sx, sy, dx, dy,
                        s->cirrus_blt_width / depth,
                        s->cirrus_blt_height);

    /* we don't have to notify the display that this portion has
       changed since dpy_copy implies this */

    if (!notify)
        cirrus_invalidate_region(s, s->cirrus_blt_dstaddr,
                                 s->cirrus_blt_dstpitch, s->cirrus_blt_width,
                                 s->cirrus_blt_height);
}
glue(cirrus_bitblt_rop_fwd_, ROP_NAME)(CirrusVGAState *s,
                                       uint8_t *dst, const uint8_t *src,
                                       int dstpitch, int srcpitch,
                                       int bltwidth, int bltheight)
{
    int x, y;
    dstpitch -= bltwidth;
    srcpitch -= bltwidth;
    for (y = 0; y < bltheight; y++)
    {
        for (x = 0; x < bltwidth; x++)
        {
            ROP_OP(*dst, *src);
            dst++;
            src++;
        }
        dst += dstpitch;
        src += srcpitch;
    }
}

static int cirrus_bitblt_videotovideo_copy(CirrusVGAState *s)
{
    if (s->ds->dpy_copy)
    {
        cirrus_do_copy(s, s->cirrus_blt_dstaddr - s->start_addr,
                       s->cirrus_blt_srcaddr - s->start_addr,
                       s->cirrus_blt_width, s->cirrus_blt_height);
    }
    else
    {
        (*s->cirrus_rop)(s, s->vram_ptr + s->cirrus_blt_dstaddr,
                         s->vram_ptr + s->cirrus_blt_srcaddr,
                         s->cirrus_blt_dstpitch, s->cirrus_blt_srcpitch,
                         s->cirrus_blt_width, s->cirrus_blt_height);

        cirrus_invalidate_region(s, s->cirrus_blt_dstaddr,
                                 s->cirrus_blt_dstpitch, s->cirrus_blt_width,
                                 s->cirrus_blt_height);
    }

    return 1;
}
static void cirrus_mem_writeb_mode4and5_8bpp(CirrusVGAState *s,
                                             unsigned mode,
                                             unsigned offset,
                                             uint32_t mem_value)
{
    int x;
    unsigned val = mem_value;
    uint8_t *dst;

    dst = s->vram_ptr + offset;
    for (x = 0; x < 8; x++)
    {
        if (val & 0x80)
        {
            *dst = s->cirrus_shadow_gr1;
        }
        else if (mode == 5)
        {
            *dst = s->cirrus_shadow_gr0;
        }
        val <<= 1;
        dst++;
    }
    cpu_physical_memory_set_dirty(s->vram_offset + offset);
    cpu_physical_memory_set_dirty(s->vram_offset + offset + 7);
}
static int cirrus_bitblt_common_patterncopy(CirrusVGAState *s,
                                            const uint8_t *src)
{
    uint8_t *dst;

    dst = s->vram_ptr + s->cirrus_blt_dstaddr;
    (*s->cirrus_rop)(s, dst, src,
                     s->cirrus_blt_dstpitch, 0,
                     s->cirrus_blt_width, s->cirrus_blt_height);
    cirrus_invalidate_region(s, s->cirrus_blt_dstaddr,
                             s->cirrus_blt_dstpitch, s->cirrus_blt_width,
                             s->cirrus_blt_height);
    return 1;
}
static void cirrus_invalidate_region(CirrusVGAState *s, int off_begin,
                                     int off_pitch, int bytesperline,
                                     int lines)
{
    int y;
    int off_cur;
    int off_cur_end;

    for (y = 0; y < lines; y++)
    {
        off_cur = off_begin;
        off_cur_end = off_cur + bytesperline;
        off_cur &= TARGET_PAGE_MASK;
        while (off_cur < off_cur_end)
        {
            cpu_physical_memory_set_dirty(s->vram_offset + off_cur);
            off_cur += TARGET_PAGE_SIZE;
        }
        off_begin += off_pitch;
    }
}

static int cirrus_bitblt_videotovideo_patterncopy(CirrusVGAState *s)
{
    return cirrus_bitblt_common_patterncopy(s,
                                            s->vram_ptr +
                                                (s->cirrus_blt_srcaddr & ~7));
}

static int cirrus_bitblt_solidfill(CirrusVGAState *s, int blt_rop)
{
    cirrus_fill_t rop_func;

    rop_func = cirrus_fill[rop_to_index[blt_rop]][s->cirrus_blt_pixelwidth - 1];
    rop_func(s, s->vram_ptr + s->cirrus_blt_dstaddr,
             s->cirrus_blt_dstpitch,
             s->cirrus_blt_width, s->cirrus_blt_height);
    cirrus_invalidate_region(s, s->cirrus_blt_dstaddr,
                             s->cirrus_blt_dstpitch, s->cirrus_blt_width,
                             s->cirrus_blt_height);
    cirrus_bitblt_reset(s);
    return 1;
}

static void cirrus_bitblt_cputovideo_next(CirrusVGAState *s)
{
    int copy_count;
    uint8_t *end_ptr;

    if (s->cirrus_srccounter > 0)
    {
        if (s->cirrus_blt_mode & CIRRUS_BLTMODE_PATTERNCOPY)
        {
            cirrus_bitblt_common_patterncopy(s, s->cirrus_bltbuf);
        the_end:
            s->cirrus_srccounter = 0;
            cirrus_bitblt_reset(s);
        }
        else
        {
            /* at least one scan line */
            do
            {
                (*s->cirrus_rop)(s, s->vram_ptr + s->cirrus_blt_dstaddr,
                                 s->cirrus_bltbuf, 0, 0, s->cirrus_blt_width, 1);
                cirrus_invalidate_region(s, s->cirrus_blt_dstaddr, 0,
                                         s->cirrus_blt_width, 1);
                s->cirrus_blt_dstaddr += s->cirrus_blt_dstpitch;
                s->cirrus_srccounter -= s->cirrus_blt_srcpitch;
                if (s->cirrus_srccounter <= 0)
                    goto the_end;
                /* more bytes than needed can be transfered because of
                   word alignment, so we keep them for the next line */
                /* XXX: keep alignment to speed up transfer */
                end_ptr = s->cirrus_bltbuf + s->cirrus_blt_srcpitch;
                copy_count = s->cirrus_srcptr_end - end_ptr;
                memmove(s->cirrus_bltbuf, end_ptr, copy_count);
                s->cirrus_srcptr = s->cirrus_bltbuf + copy_count;
                s->cirrus_srcptr_end = s->cirrus_bltbuf + s->cirrus_blt_srcpitch;
            } while (s->cirrus_srcptr >= s->cirrus_srcptr_end);
        }
    }
}
static void cirrus_mem_writeb_mode4and5_16bpp(CirrusVGAState *s,
                                              unsigned mode,
                                              unsigned offset,
                                              uint32_t mem_value)
{
    int x;
    unsigned val = mem_value;
    uint8_t *dst;

    dst = s->vram_ptr + offset;
    for (x = 0; x < 8; x++)
    {
        if (val & 0x80)
        {
            *dst = s->cirrus_shadow_gr1;
            *(dst + 1) = s->gr[0x11];
        }
        else if (mode == 5)
        {
            *dst = s->cirrus_shadow_gr0;
            *(dst + 1) = s->gr[0x10];
        }
        val <<= 1;
        dst += 2;
    }
    cpu_physical_memory_set_dirty(s->vram_offset + offset);
    cpu_physical_memory_set_dirty(s->vram_offset + offset + 15);
}

static int cirrus_bitblt_videotovideo_copy(CirrusVGAState *s)
{
    if (s->ds->dpy_copy)
    {
        cirrus_do_copy(s, s->cirrus_blt_dstaddr - s->start_addr,
                       s->cirrus_blt_srcaddr - s->start_addr,
                       s->cirrus_blt_width, s->cirrus_blt_height);
    }
    else
    {

        if (BLTUNSAFE(s))
            return 0;

        (*s->cirrus_rop)(s, s->vram_ptr + (s->cirrus_blt_dstaddr & s->cirrus_addr_mask),
                         s->vram_ptr +
                             (s->cirrus_blt_srcaddr & s->cirrus_addr_mask),
                         s->cirrus_blt_dstpitch, s->cirrus_blt_srcpitch,
                         s->cirrus_blt_width, s->cirrus_blt_height);

        cirrus_invalidate_region(s, s->cirrus_blt_dstaddr,
                                 s->cirrus_blt_dstpitch, s->cirrus_blt_width,
                                 s->cirrus_blt_height);
    }

    return 1;
}
asmlinkage long compat_sys_mount(char __user *dev_name, char __user *dir_name,
                                 char __user *type, unsigned long flags,
                                 void __user *data)
{
    unsigned long type_page;
    unsigned long data_page;
    unsigned long dev_page;
    char *dir_page;
    int retval;

    retval = copy_mount_options(type, &type_page);
    if (retval < 0)
        goto out;

    dir_page = getname(dir_name);
    retval = PTR_ERR(dir_page);
    if (IS_ERR(dir_page))
        goto out1;

    retval = copy_mount_options(dev_name, &dev_page);
    if (retval < 0)
        goto out2;

    retval = copy_mount_options(data, &data_page);
    if (retval < 0)
        goto out3;

    retval = -EINVAL;

    if (type_page)
    {
        if (!strcmp((char *)type_page, SMBFS_NAME))
        {
            do_smb_super_data_conv((void *)data_page);
        }
        else if (!strcmp((char *)type_page, NCPFS_NAME))
        {
            do_ncp_super_data_conv((void *)data_page);
        }
        else if (!strcmp((char *)type_page, NFS4_NAME))
        {
            if (do_nfs4_super_data_conv((void *)data_page))
                goto out4;
        }
    }

    lock_kernel();
    retval = do_mount((char *)dev_page, dir_page, (char *)type_page,
                      flags, (void *)data_page);
    unlock_kernel();

out4:
    free_page(data_page);
out3:
    free_page(dev_page);
out2:
    putname(dir_page);
out1:
    free_page(type_page);
out:
    return retval;
}

unsigned short atalk_checksum(struct ddpehdr *ddp, int len)
{
    unsigned long sum = 0; /* Assume unsigned long is >16 bits */
    unsigned char *data = (unsigned char *)ddp;

    len -= 4; /* skip header 4 bytes */
    data += 4;

    /* This ought to be unwrapped neatly. I'll trust gcc for now */
    while (len--)
    {
        sum += *data;
        sum <<= 1;
        if (sum & 0x10000)
        {
            sum++;
            sum &= 0xFFFF;
        }
        data++;
    }
    /* Use 0xFFFF for 0. 0 itself means none */
    return sum ? htons((unsigned short)sum) : 0xFFFF;
}
static int ltalk_rcv(struct sk_buff *skb, struct net_device *dev,
                     struct packet_type *pt)
{
    /* Expand any short form frames */
    if (skb->mac.raw[2] == 1)
    {
        struct ddpehdr *ddp;
        /* Find our address */
        struct atalk_addr *ap = atalk_find_dev_addr(dev);

        if (!ap || skb->len < sizeof(struct ddpshdr))
            goto freeit;
        /*
         * The push leaves us with a ddephdr not an shdr, and
         * handily the port bytes in the right place preset.
         */

        skb_push(skb, sizeof(*ddp) - 4);
        /* FIXME: use skb->cb to be able to use shared skbs */
        ddp = (struct ddpehdr *)skb->data;

        /* Now fill in the long header */

        /*
         * These two first. The mac overlays the new source/dest
         * network information so we MUST copy these before
         * we write the network numbers !
         */

        ddp->deh_dnode = skb->mac.raw[0]; /* From physical header */
        ddp->deh_snode = skb->mac.raw[1]; /* From physical header */

        ddp->deh_dnet = ap->s_net; /* Network number */
        ddp->deh_snet = ap->s_net;
        ddp->deh_sum = 0; /* No checksum */
        /*
         * Not sure about this bit...
         */
        ddp->deh_len = skb->len;
        ddp->deh_hops = DDP_MAXHOPS; /* Non routable, so force a drop
                        if we slip up later */
        /* Mend the byte order */
        *((__u16 *)ddp) = htons(*((__u16 *)ddp));
    }
    skb->h.raw = skb->data;

    return atalk_rcv(skb, dev, pt);
freeit:
    kfree_skb(skb);
    return 0;
}
static int atalk_rcv(struct sk_buff *skb, struct net_device *dev,
                     struct packet_type *pt)
{
    struct ddpehdr *ddp = ddp_hdr(skb);
    struct sock *sock;
    struct atalk_iface *atif;
    struct sockaddr_at tosat;
    int origlen;
    struct ddpebits ddphv;

    /* Size check */
    if (skb->len < sizeof(*ddp))
        goto freeit;

    /*
     *        Fix up the length field        [Ok this is horrible but otherwise
     *        I end up with unions of bit fields and messy bit field order
     *        compiler/endian dependencies..]
     *
     *        FIXME: This is a write to a shared object. Granted it
     *        happens to be safe BUT.. (Its safe as user space will not
     *        run until we put it back)
     */
    *((__u16 *)&ddphv) = ntohs(*((__u16 *)ddp));

    /* Trim buffer in case of stray trailing data */
    origlen = skb->len;
    skb_trim(skb, min_t(unsigned int, skb->len, ddphv.deh_len));

    /*
     * Size check to see if ddp->deh_len was crap
     * (Otherwise we'll detonate most spectacularly
     * in the middle of recvmsg()).
     */
    if (skb->len < sizeof(*ddp))
        goto freeit;

    /*
     * Any checksums. Note we don't do htons() on this == is assumed to be
     * valid for net byte orders all over the networking code...
     */
    if (ddp->deh_sum &&
        atalk_checksum(ddp, ddphv.deh_len) != ddp->deh_sum)
        /* Not a valid AppleTalk frame - dustbin time */
        goto freeit;

    /* Check the packet is aimed at us */
    if (!ddp->deh_dnet) /* Net 0 is 'this network' */
        atif = atalk_find_anynet(ddp->deh_dnode, dev);
    else
        atif = atalk_find_interface(ddp->deh_dnet, ddp->deh_dnode);

    /* Not ours, so we route the packet via the correct AppleTalk iface */
    if (!atif)
    {
        atalk_route_packet(skb, dev, ddp, &ddphv, origlen);
        goto out;
    }

    /* if IP over DDP is not selected this code will be optimized out */
    if (is_ip_over_ddp(skb))
        return handle_ip_over_ddp(skb);
    /*
     * Which socket - atalk_search_socket() looks for a *full match*
     * of the <net, node, port> tuple.
     */
    tosat.sat_addr.s_net = ddp->deh_dnet;
    tosat.sat_addr.s_node = ddp->deh_dnode;
    tosat.sat_port = ddp->deh_dport;

    sock = atalk_search_socket(&tosat, atif);
    if (!sock) /* But not one of our sockets */
        goto freeit;

    /* Queue packet (standard) */
    skb->sk = sock;

    if (sock_queue_rcv_skb(sock, skb) < 0)
        goto freeit;
out:
    return 0;
freeit:
    kfree_skb(skb);
    goto out;
}
static int atalk_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
                         int len)
{
    struct sock *sk = sock->sk;
    struct atalk_sock *at = at_sk(sk);
    struct sockaddr_at *usat = (struct sockaddr_at *)msg->msg_name;
    int flags = msg->msg_flags;
    int loopback = 0;
    struct sockaddr_at local_satalk, gsat;
    struct sk_buff *skb;
    struct net_device *dev;
    struct ddpehdr *ddp;
    int size;
    struct atalk_route *rt;
    int err;

    if (flags & ~MSG_DONTWAIT)
        return -EINVAL;

    if (len > DDP_MAXSZ)
        return -EMSGSIZE;

    if (usat)
    {
        if (sk->sk_zapped)
            if (atalk_autobind(sk) < 0)
                return -EBUSY;

        if (msg->msg_namelen < sizeof(*usat) ||
            usat->sat_family != AF_APPLETALK)
            return -EINVAL;

        /* netatalk doesn't implement this check */
        if (usat->sat_addr.s_node == ATADDR_BCAST &&
            !sock_flag(sk, SOCK_BROADCAST))
        {
            printk(KERN_INFO "" SO_BROADCAST : Fix your netatalk as ""
                                                                    "" it will break before 2.2\n "");
#if 0
			return -EPERM;
#endif
        }
    }
    else
    {
        if (sk->sk_state != TCP_ESTABLISHED)
            return -ENOTCONN;
        usat = &local_satalk;
        usat->sat_family = AF_APPLETALK;
        usat->sat_port = at->dest_port;
        usat->sat_addr.s_node = at->dest_node;
        usat->sat_addr.s_net = at->dest_net;
    }

    /* Build a packet */
    SOCK_DEBUG(sk, "" SK % p : Got address.\n "", sk);

    /* For headers */
    size = sizeof(struct ddpehdr) + len + ddp_dl->header_length;

    if (usat->sat_addr.s_net || usat->sat_addr.s_node == ATADDR_ANYNODE)
    {
        rt = atrtr_find(&usat->sat_addr);
        if (!rt)
            return -ENETUNREACH;

        dev = rt->dev;
    }
    else
    {
        struct atalk_addr at_hint;

        at_hint.s_node = 0;
        at_hint.s_net = at->src_net;

        rt = atrtr_find(&at_hint);
        if (!rt)
            return -ENETUNREACH;

        dev = rt->dev;
    }

    SOCK_DEBUG(sk, "" SK % p : Size needed % d, device % s\n "",
               sk, size, dev->name);

    size += dev->hard_header_len;
    skb = sock_alloc_send_skb(sk, size, (flags & MSG_DONTWAIT), &err);
    if (!skb)
        return err;

    skb->sk = sk;
    skb_reserve(skb, ddp_dl->header_length);
    skb_reserve(skb, dev->hard_header_len);
    skb->dev = dev;

    SOCK_DEBUG(sk, "" SK % p : Begin build.\n "", sk);

    ddp = (struct ddpehdr *)skb_put(skb, sizeof(struct ddpehdr));
    ddp->deh_pad = 0;
    ddp->deh_hops = 0;
    ddp->deh_len = len + sizeof(*ddp);
    /*
     * Fix up the length field [Ok this is horrible but otherwise
     * I end up with unions of bit fields and messy bit field order
     * compiler/endian dependencies..
     */
    *((__u16 *)ddp) = ntohs(*((__u16 *)ddp));

    ddp->deh_dnet = usat->sat_addr.s_net;
    ddp->deh_snet = at->src_net;
    ddp->deh_dnode = usat->sat_addr.s_node;
    ddp->deh_snode = at->src_node;
    ddp->deh_dport = usat->sat_port;
    ddp->deh_sport = at->src_port;

    SOCK_DEBUG(sk, "" SK % p : Copy user data(% d bytes).\n "", sk, len);

    err = memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len);
    if (err)
    {
        kfree_skb(skb);
        return -EFAULT;
    }

    if (sk->sk_no_check == 1)
        ddp->deh_sum = 0;
    else
        ddp->deh_sum = atalk_checksum(ddp, len + sizeof(*ddp));

    /*
     * Loopback broadcast packets to non gateway targets (ie routes
     * to group we are in)
     */
    if (ddp->deh_dnode == ATADDR_BCAST &&
        !(rt->flags & RTF_GATEWAY) && !(dev->flags & IFF_LOOPBACK))
    {
        struct sk_buff *skb2 = skb_copy(skb, GFP_KERNEL);

        if (skb2)
        {
            loopback = 1;
            SOCK_DEBUG(sk, "" SK % p : send out(copy).\n "", sk);
            if (aarp_send_ddp(dev, skb2,
                              &usat->sat_addr, NULL) == -1)
                kfree_skb(skb2);
            /* else queued/sent above in the aarp queue */
        }
    }

    if (dev->flags & IFF_LOOPBACK || loopback)
    {
        SOCK_DEBUG(sk, "" SK % p : Loop back.\n "", sk);
        /* loop back */
        skb_orphan(skb);
        ddp_dl->request(ddp_dl, skb, dev->dev_addr);
    }
    else
    {
        SOCK_DEBUG(sk, "" SK % p : send out.\n "", sk);
        if (rt->flags & RTF_GATEWAY)
        {
            gsat.sat_addr = rt->gateway;
            usat = &gsat;
        }

        if (aarp_send_ddp(dev, skb, &usat->sat_addr, NULL) == -1)
            kfree_skb(skb);
        /* else queued/sent above in the aarp queue */
    }
    SOCK_DEBUG(sk, "" SK % p : Done write(% d).\n "", sk, len);

    return len;
}
static int fat_ioctl_filldir(void *__buf, const char *name, int name_len,
                             loff_t offset, u64 ino, unsigned int d_type)
{
    struct fat_ioctl_filldir_callback *buf = __buf;
    struct dirent __user *d1 = buf->dirent;
    struct dirent __user *d2 = d1 + 1;

    if (buf->result)
        return -EINVAL;
    buf->result++;

    if (name != NULL)
    {
        /* dirent has only short name */
        if (name_len >= sizeof(d1->d_name))
            name_len = sizeof(d1->d_name) - 1;

        if (put_user(0, d2->d_name) ||
            put_user(0, &d2->d_reclen) ||
            copy_to_user(d1->d_name, name, name_len) ||
            put_user(0, d1->d_name + name_len) ||
            put_user(name_len, &d1->d_reclen))
            goto efault;
    }
    else
    {
        /* dirent has short and long name */
        const char *longname = buf->longname;
        int long_len = buf->long_len;
        const char *shortname = buf->shortname;
        int short_len = buf->short_len;

        if (long_len >= sizeof(d1->d_name))
            long_len = sizeof(d1->d_name) - 1;
        if (short_len >= sizeof(d1->d_name))
            short_len = sizeof(d1->d_name) - 1;

        if (copy_to_user(d2->d_name, longname, long_len) ||
            put_user(0, d2->d_name + long_len) ||
            put_user(long_len, &d2->d_reclen) ||
            put_user(ino, &d2->d_ino) ||
            put_user(offset, &d2->d_off) ||
            copy_to_user(d1->d_name, shortname, short_len) ||
            put_user(0, d1->d_name + short_len) ||
            put_user(short_len, &d1->d_reclen))
            goto efault;
    }
    return 0;
efault:
    buf->result = -EFAULT;
    return -EFAULT;
}
static int fat_dir_ioctl(struct inode *inode, struct file *filp,
                         unsigned int cmd, unsigned long arg)
{
    struct fat_ioctl_filldir_callback buf;
    struct dirent __user *d1;
    int ret, short_only, both;

    switch (cmd)
    {
    case VFAT_IOCTL_READDIR_SHORT:
        short_only = 1;
        both = 0;
        break;
    case VFAT_IOCTL_READDIR_BOTH:
        short_only = 0;
        both = 1;
        break;
    default:
        return fat_generic_ioctl(inode, filp, cmd, arg);
    }

    d1 = (struct dirent __user *)arg;
    if (!access_ok(VERIFY_WRITE, d1, sizeof(struct dirent[2])))
        return -EFAULT;
    /*
     * Yes, we don't need this put_user() absolutely. However old
     * code didn't return the right value. So, app use this value,
     * in order to check whether it is EOF.
     */
    if (put_user(0, &d1->d_reclen))
        return -EFAULT;

    buf.dirent = d1;
    buf.result = 0;
    mutex_lock(&inode->i_mutex);
    ret = -ENOENT;
    if (!IS_DEADDIR(inode))
    {
        ret = __fat_readdir(inode, filp, &buf, fat_ioctl_filldir,
                            short_only, both);
    }
    mutex_unlock(&inode->i_mutex);
    if (ret >= 0)
        ret = buf.result;
    return ret;
}
static long fat_compat_dir_ioctl(struct file *file, unsigned cmd,
                                 unsigned long arg)
{
    struct compat_dirent __user *p = compat_ptr(arg);
    int ret;
    mm_segment_t oldfs = get_fs();
    struct dirent d[2];

    switch (cmd)
    {
    case VFAT_IOCTL_READDIR_BOTH32:
        cmd = VFAT_IOCTL_READDIR_BOTH;
        break;
    case VFAT_IOCTL_READDIR_SHORT32:
        cmd = VFAT_IOCTL_READDIR_SHORT;
        break;
    default:
        return -ENOIOCTLCMD;
    }

    set_fs(KERNEL_DS);
    lock_kernel();
    ret = fat_dir_ioctl(file->f_path.dentry->d_inode, file,
                        cmd, (unsigned long)&d);
    unlock_kernel();
    set_fs(oldfs);
    if (ret >= 0)
    {
        ret |= fat_compat_put_dirent32(&d[0], p);
        ret |= fat_compat_put_dirent32(&d[1], p + 1);
    }
    return ret;
}
static long fat_compat_put_dirent32(struct dirent *d,
                                    struct compat_dirent __user *d32)
{
    if (!access_ok(VERIFY_WRITE, d32, sizeof(struct compat_dirent)))
        return -EFAULT;

    __put_user(d->d_ino, &d32->d_ino);
    __put_user(d->d_off, &d32->d_off);
    __put_user(d->d_reclen, &d32->d_reclen);
    if (__copy_to_user(d32->d_name, d->d_name, d->d_reclen))
        return -EFAULT;

    return 0;
}

static int vfat_ioctl32(unsigned fd, unsigned cmd, unsigned long arg)
{
    struct compat_dirent __user *p = compat_ptr(arg);
    int ret;
    mm_segment_t oldfs = get_fs();
    struct dirent d[2];

    switch (cmd)
    {
    case VFAT_IOCTL_READDIR_BOTH32:
        cmd = VFAT_IOCTL_READDIR_BOTH;
        break;
    case VFAT_IOCTL_READDIR_SHORT32:
        cmd = VFAT_IOCTL_READDIR_SHORT;
        break;
    }

    set_fs(KERNEL_DS);
    ret = sys_ioctl(fd, cmd, (unsigned long)&d);
    set_fs(oldfs);
    if (ret >= 0)
    {
        ret |= put_dirent32(&d[0], p);
        ret |= put_dirent32(&d[1], p + 1);
    }
    return ret;
}

put_dirent32(struct dirent *d, struct compat_dirent __user *d32)
{
    if (!access_ok(VERIFY_WRITE, d32, sizeof(struct compat_dirent)))
        return -EFAULT;

    __put_user(d->d_ino, &d32->d_ino);
    __put_user(d->d_off, &d32->d_off);
    __put_user(d->d_reclen, &d32->d_reclen);
    if (__copy_to_user(d32->d_name, d->d_name, d->d_reclen))
        return -EFAULT;

    return 0;
}
