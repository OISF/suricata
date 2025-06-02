Util
####

The ``suricata.util`` library provides utility functions for Lua
scripts.

Setup
*****

The library must be loaded prior to use::

    local util = require("suricata.util")

Functions
=========

.. function:: thread_info()

   Get information about the current thread.

   :returns: Table containing thread information with the following fields:

      - ``id`` (number): Thread ID
      - ``name`` (string): Thread name 
      - ``group_name`` (string): Thread group name
            
   Example::

       local util = require("suricata.util")
       
       local info = util.thread_info()
       print("Thread ID: " .. info.id)
       print("Thread Name: " .. info.name)
       print("Thread Group: " .. info.group_name)
