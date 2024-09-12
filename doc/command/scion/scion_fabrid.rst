:orphan:

.. _scion_fabrid:

scion fabrid
------------

Display FABRID policy information

Synopsis
~~~~~~~~


'fabrid' lists available policies at a remote AS, or shows the
description of a specific policy.

::

  scion fabrid [flags]

Examples
~~~~~~~~

::

    scion showpaths 1-ff00:0:110 --extended
    scion showpaths 1-ff00:0:110 --local 127.0.0.55 --json
    scion showpaths 1-ff00:0:111 --sequence="0-0#2 0*" # outgoing IfID=2
    scion showpaths 1-ff00:0:111 --sequence="0* 0-0#41" # incoming IfID=41 at dstIA
    scion showpaths 1-ff00:0:111 --sequence="0* 1-ff00:0:112 0*" # 1-ff00:0:112 on the path
    scion showpaths 1-ff00:0:110 --no-probe

Options
~~~~~~~

::

      --epic                   Enable EPIC.
  -e, --extended               Show extended path meta data information
      --format string          Specify the output format (human|json|yaml) (default "human")
  -h, --help                   help for fabrid
      --isd-as isd-as          The local ISD-AS to use. (default 0-0)
  -l, --local ip               Local IP address to listen on. (default invalid IP)
      --log.level string       Console logging level verbosity (debug|info|error)
  -m, --maxpaths int           Maximum number of paths that are displayed (default 10)
      --no-color               disable colored output
      --no-probe               Do not probe the paths and print the health status
  -r, --refresh                Set refresh flag for SCION Daemon path request
      --sciond string          SCION Daemon address. (default "127.0.0.1:30255")
      --sequence string        Space separated list of hop predicates
      --timeout duration       Timeout (default 5s)
      --tracing.agent string   Tracing agent address

SEE ALSO
~~~~~~~~

* :ref:`scion <scion>` 	 - SCION networking utilities.

