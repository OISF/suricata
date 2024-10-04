Top Level (object)
^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ======= ===========
   Name     Type    Description
   ======== ======= ===========
   request  object             
   response object             
   tx_id    integer            
   ======== ======= ===========

response (object)
^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========================== ================ ===========
   Name                        Type             Description
   =========================== ================ ===========
   authentication_md5_password string                      
   authentication_sasl_final   string                      
   code                        string                      
   command_completed           string                      
   data_rows                   integer                     
   data_size                   integer                     
   field_count                 integer                     
   file                        string                      
   line                        string                      
   message                     string                      
   parameter_status            array of objects            
   process_id                  integer                     
   routine                     string                      
   secret_key                  integer                     
   severity_localizable        string                      
   severity_non_localizable    string                      
   ssl_accepted                boolean                     
   =========================== ================ ===========

response.parameter_status (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========================== ====== ===========
   Name                        Type   Description
   =========================== ====== ===========
   application_name            string            
   client_encoding             string            
   date_style                  string            
   integer_datetimes           string            
   interval_style              string            
   is_superuser                string            
   server_encoding             string            
   server_version              string            
   session_authorization       string            
   standard_conforming_strings string            
   time_zone                   string            
   =========================== ====== ===========

request (object)
^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============================= ======= ===========
   Name                          Type    Description
   ============================= ======= ===========
   message                       string             
   password                      string             
   password_message              string             
   process_id                    integer            
   protocol_version              string             
   sasl_authentication_mechanism string             
   sasl_param                    string             
   sasl_response                 string             
   secret_key                    integer            
   simple_query                  string             
   startup_parameters            object             
   ============================= ======= ===========

request.startup_parameters (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =================== ================ ===========
   Name                Type             Description
   =================== ================ ===========
   optional_parameters array of objects            
   user                string                      
   =================== ================ ===========

request.startup_parameters.optional_parameters (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================== ====== ===========
   Name               Type   Description
   ================== ====== ===========
   application_name   string            
   client_encoding    string            
   database           string            
   datestyle          string            
   extra_float_digits string            
   options            string            
   replication        string            
   ================== ====== ===========

