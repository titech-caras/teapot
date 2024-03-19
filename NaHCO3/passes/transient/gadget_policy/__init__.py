from .transient_kasper_policy_pass import TransientKasperPolicyPass
from .transient_specfuzz_policy_pass import TransientSpecFuzzPolicyPass


class GadgetPolicyFactory:
    __policy_dict__ = {
        'SpecFuzz': TransientSpecFuzzPolicyPass,
        'Kasper': TransientKasperPolicyPass
    }

    @classmethod
    def get(cls, name: str):
        if name not in cls.__policy_dict__:
            raise NotImplementedError

        return cls.__policy_dict__[name]

