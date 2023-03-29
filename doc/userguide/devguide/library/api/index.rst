API
===

When used as a library, suricata exports the provided API in the *suricata-interface.h* header.
The following sections describe in details the exported methods and how a client should invoke
them to properly integrate the library. Notice that the order in which these methods are described
is the same a client **must** use when invoking them.

.. toctree::
   :maxdepth: 3

   context_creation
   configuration
   callbacks/index.rst
   initialization
   input
   rule_reload
   stats
   cleanup