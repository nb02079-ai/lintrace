"""구현된 점검 항목 등록부. 새 항목을 만들면 여기 ALL_CHECKS에 추가한다."""
from .acc_01 import Acc01
from .acc_06 import Acc06
from .acc_07 import Acc07
from .per_01 import Per01
from .per_05 import Per05

ALL_CHECKS = [Acc01, Acc06, Acc07, Per01, Per05]
