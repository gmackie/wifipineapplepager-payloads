"""Protocol adapters for the ICS probe."""
from .modbus_rtu import ModbusRTUAdapter
from .can import CANAdapter
from .dio import DIOAdapter
from .current_output import CurrentOutputAdapter
from .ethernet import EthernetAdapter

ADAPTER_REGISTRY = {
    "modbus-rtu": ModbusRTUAdapter,
    "can": CANAdapter,
    "digital-io": DIOAdapter,
    "analog-output": CurrentOutputAdapter,
    "modbus-tcp": EthernetAdapter,
}
