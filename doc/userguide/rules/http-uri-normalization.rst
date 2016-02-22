HTTP-uri normalization
======================

The uri has two appearances in Suricata: the raw_uri and the
normalized uri. The space for example can be indicated with the
heximal notation %20. To convert this notation in a space, means
normalizing it. It is possible though to match specific on the
characters %20 in a uri. This means matching on the raw_uri.  The
raw_uri and the normalized uri are separate buffers. So, the raw_uri
inspects the raw_uri buffer and can not inspect the normalized buffer.
