Top Level (object)
^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ================ ================================================================
   Name       Type             Description                                                     
   ========== ================ ================================================================
   cyu        array of objects ja3-like fingerprint for versions of QUIC before standardization
   extensions array of objects list of extensions in hello                                     
   ja3        object           ja3 from client, as in TLS                                      
   ja3s       object           ja3 from server, as in TLS                                      
   ja4        string                                                                           
   sni        string           Server Name Indication                                          
   ua         string           User Agent for versions of QUIC before standardization          
   version    string           Quic protocol version                                           
   ========== ================ ================================================================

ja3s (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ====== ==========================
   Name   Type   Description               
   ====== ====== ==========================
   hash   string ja3s hex representation   
   string string ja3s string representation
   ====== ====== ==========================

ja3 (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ====== =========================
   Name   Type   Description              
   ====== ====== =========================
   hash   string ja3 hex representation   
   string string ja3 string representation
   ====== ====== =========================

extensions (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ================ ====================================
   Name   Type             Description                         
   ====== ================ ====================================
   name   string           human-friendly name of the extension
   type   integer          integer identifier of the extension 
   values array of strings extension values                    
   ====== ================ ====================================

cyu (array of objects)
^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ====== ==============================
   Name   Type   Description                   
   ====== ====== ==============================
   hash   string cyu hash hex representation   
   string string cyu hash string representation
   ====== ====== ==============================

