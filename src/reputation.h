#ifndef __REPUTATION_H__
#define __REPUTATION_H__

/** \file
 *  \author Victor Julien
 *
 *  General reputation for ip's (ipv4/ipv6) and (maybe later) host names
 */

/* Reputation numbers that we can use to lookup the reps in an array */

#define REPUTATION_SPAM             0   /**< spammer */
#define REPUTATION_CNC              1   /**< CnC server */
#define REPUTATION_SCAN             2   /**< scanner */
#define REPUTATION_HOSTILE          3   /**< hijacked nets, RBN nets, etc */
#define REPUTATION_DYNAMIC          4   /**< Known dial up, residential, user networks */
#define REPUTATION_PUBLICACCESS     5   /**< known internet cafe's open access points */
#define REPUTATION_PROXY            6   /**< known tor out nodes, proxy servers, etc */
#define REPUTATION_P2P              7   /**< Heavy p2p node, torrent server, other sharing services */
#define REPUTATION_UTILITY          8   /**< known good places like google, yahoo, msn.com, etc */
#define REPUTATION_DDOS             9   /**< Known ddos participant. */
#define REPUTATION_PHISH            10  /**< Known Phishing site. */
#define REPUTATION_MALWARE          11  /**< Known Malware distribution site. (Hacked web server etc) */
#define REPUTATION_ZOMBIE           12  /**< Known Zombie (botnet member) (They typically are Scanner or Hostile,
                                             but if collaboration with botnet snooping, like we did back in
                                             2005 or so, can proactively identify online zombies that joined a
                                             botnet, you may want to break those out separately.) */
#define REPUTATION_NUMBER           13  /**< number of rep types we have for data structure size */

#define REPUTATION_FLAG_NEEDSYNC    0x01 /**< rep was changed by engine, needs sync with external hub */

typedef struct Reputation_ {
    uint8_t reps[REPUTATION_NUMBER]; /**< array of 8 bit reputations */
    uint8_t flags; /**< reputation flags */
} Reputation;

#endif /* __REPUTATION_H__ */
