DNP3 Keywords
=============

The DNP3 keywords can be used to match on fields in decoded DNP3
messages. The keywords are based on Snort's DNP3 keywords and aim to
be 100% compatible.

dnp3_func
---------

This keyword will match on the application function code found in DNP3
request and responses.  It can be specified as the integer value or
the symbolic name of the function code.

Syntax
~~~~~~

::

  dnp3_func:<value>;

Where value is one of:

* An integer value between 0 and 255 inclusive.
* Function code name:

  * confirm
  * read
  * write
  * select
  * operate
  * direct_operate
  * direct_operate_nr
  * immed_freeze
  * immed_freeze_nr
  * freeze_clear
  * freeze_clear_nr
  * freeze_at_time
  * freeze_at_time_nr
  * cold_restart
  * warm_restart
  * initialize_data
  * initialize_appl
  * start_appl
  * stop_appl
  * save_config
  * enable_unsolicited
  * disable_unsolicited
  * assign_class
  * delay_measure
  * record_current_time
  * open_file
  * close_file
  * delete_file
  * get_file_info
  * authenticate_file
  * abort_file
  * activate_config
  * authenticate_req
  * authenticate_err
  * response
  * unsolicited_response
  * authenticate_resp

dnp3_ind
--------

This keyword matches on the DNP3 internal indicator flags in the
response application header.

Syntax
~~~~~~

::

  dnp3_ind:<flag>{,<flag>...}


Where flag is the name of the internal indicator:

* all_stations
* class_1_events
* class_2_events
* class_3_events
* need_time
* local_control
* device_trouble
* device_restart
* no_func_code_support
* object_unknown
* parameter_error
* event_buffer_overflow
* already_executing
* config_corrupt
* reserved_2
* reserved_1

This keyword will match of any of the flags listed are set. To match
on multiple flags (AND type match), use dnp3_ind for each flag that
must be set.

Examples
~~~~~~~~

::

  dnp3_ind:all_stations;

::

  dnp3_ind:class_1_events,class_2_events;

dnp3_obj
--------

This keyword matches on the DNP3 application data objects.

Syntax
~~~~~~

::


  dnp3_obj:<group>,<variation>

Where <group> and <variation> are integer values between 0 and 255 inclusive.

dnp3_data
---------

This keyword will cause the following content options to match on the
re-assembled application buffer. The reassembled application buffer is
a DNP3 fragment with CRCs removed (which occur every 16 bytes), and
will be the complete fragment, possibly reassembled from multiple DNP3
link layer frames.

Syntax
~~~~~~

::

  dnp3_data;

Example
~~~~~~~

::

  dnp3_data; content:|c3 06|;
