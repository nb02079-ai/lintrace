"""구현된 점검 항목 등록부. 새 항목을 만들면 여기 ALL_CHECKS에 추가한다."""
from .acc_01 import Acc01
from .acc_02 import Acc02
from .acc_03 import Acc03
from .acc_04 import Acc04
from .acc_05 import Acc05
from .acc_06 import Acc06
from .acc_07 import Acc07
from .acc_08 import Acc08
from .acc_09 import Acc09
from .acc_10 import Acc10
from .acc_11 import Acc11
from .fs_02 import Fs02
from .fs_04 import Fs04
from .fs_05 import Fs05
from .fs_06 import Fs06
from .log_01 import Log01
from .per_01 import Per01
from .per_02 import Per02
from .per_03 import Per03
from .per_04 import Per04
from .per_05 import Per05
from .per_06 import Per06
from .per_07 import Per07
from .per_08 import Per08
from .per_09 import Per09
from .prc_01 import Prc01
from .prc_02 import Prc02
from .prc_03 import Prc03
from .prc_04 import Prc04
from .prc_05 import Prc05
from .prc_06 import Prc06
from .prc_07 import Prc07
from .prc_08 import Prc08
from .prc_09 import Prc09
from .net_01 import Net01
from .net_02 import Net02
from .net_06 import Net06

ALL_CHECKS = [Acc01, Acc02, Acc03, Acc04, Acc05, Acc06, Acc07, Acc08, Acc09, Acc10, Acc11, Per01, Per02, Per03, Per04, Per05, Per06, Per07,
              Per08, Per09, Prc01, Prc02, Prc03, Prc04, Prc05, Prc06, Prc07, Prc08, Prc09, Fs02, Fs04, Fs05, Fs06, Log01,
              Net01, Net02, Net06]
