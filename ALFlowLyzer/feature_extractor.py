#!/usr/bin/env python3

import warnings
from datetime import datetime
from multiprocessing import Lock
from .features import *


class FeatureExtractor(object):
    def __init__(self, floating_point_unit: str):
        warnings.filterwarnings("ignore")
        self.floating_point_unit = floating_point_unit
        self.__features = [
                Duration(),
                PacketsNumbers(),
                ReceivingPacketsNumbers(),
                SendingPacketsNumbers(),
                HandshakeDuration(),
                DeltaStart(),
                TotalBytes(),
                ReceivingBytes(),
                SendingBytes(),
                PacketsRate(),
                ReceivingPacketsRate(),
                SendingPacketsRate(),
                PacketsLenRate(),
                ReceivingPacketsLenRate(),
                SendingPacketsLenRate(),
                PacketsLenMin(),
                PacketsLenMax(),
                PacketsLenMean(),
                PacketsLenMedian(),
                PacketsLenMode(),
                PacketsLenStandardDeviation(),
                PacketsLenVariance(),
                PacketsLenCoefficientOfVariation(),
                PacketsLenSkewness(),
                ReceivingPacketsLenMin(),
                ReceivingPacketsLenMax(),
                ReceivingPacketsLenMean(),
                ReceivingPacketsLenMedian(),
                ReceivingPacketsLenMode(),
                ReceivingPacketsLenStandardDeviation(),
                ReceivingPacketsLenVariance(),
                ReceivingPacketsLenCoefficientOfVariation(),
                ReceivingPacketsLenSkewness(),
                SendingPacketsLenMin(),
                SendingPacketsLenMax(),
                SendingPacketsLenMean(),
                SendingPacketsLenMedian(),
                SendingPacketsLenMode(),
                SendingPacketsLenStandardDeviation(),
                SendingPacketsLenVariance(),
                SendingPacketsLenCoefficientOfVariation(),
                SendingPacketsLenSkewness(),
                ReceivingPacketsDeltaLenMin(),
                ReceivingPacketsDeltaLenMax(),
                ReceivingPacketsDeltaLenMean(),
                ReceivingPacketsDeltaLenMedian(),
                ReceivingPacketsDeltaLenStandardDeviation(),
                ReceivingPacketsDeltaLenVariance(),
                ReceivingPacketsDeltaLenMode(),
                ReceivingPacketsDeltaLenCoefficientOfVariation(),
                ReceivingPacketsDeltaLenSkewness(),
                SendingPacketsDeltaLenMin(),
                SendingPacketsDeltaLenMax(),
                SendingPacketsDeltaLenMean(),
                SendingPacketsDeltaLenMedian(),
                SendingPacketsDeltaLenStandardDeviation(),
                SendingPacketsDeltaLenVariance(),
                SendingPacketsDeltaLenMode(),
                SendingPacketsDeltaLenCoefficientOfVariation(),
                SendingPacketsDeltaLenSkewness(),
                ReceivingPacketsDeltaTimeMax(),
                ReceivingPacketsDeltaTimeMean(),
                ReceivingPacketsDeltaTimeMedian(),
                ReceivingPacketsDeltaTimeStandardDeviation(),
                ReceivingPacketsDeltaTimeVariance(),
                ReceivingPacketsDeltaTimeMode(),
                ReceivingPacketsDeltaTimeCoefficientOfVariation(),
                ReceivingPacketsDeltaTimeSkewness(),
                SendingPacketsDeltaTimeMin(),
                SendingPacketsDeltaTimeMax(),
                SendingPacketsDeltaTimeMean(),
                SendingPacketsDeltaTimeMedian(),
                SendingPacketsDeltaTimeStandardDeviation(),
                SendingPacketsDeltaTimeVariance(),
                SendingPacketsDeltaTimeMode(),
                SendingPacketsDeltaTimeCoefficientOfVariation(),
                SendingPacketsDeltaTimeSkewness(),
            ]
        self.__dns_features = [
                DomainName(),
                WhoisDomainName(),
                TopLevelDomain(),
                SecondLevelDomain(),
                DomainNameLen(),
                SubDomainNameLen(),
                UniGramDomainName(),
                BiGramDomainName(),
                TriGramDomainName(),
                NumericalPercentage(),
                CharacterDistribution(),
                DomainEmail(),
                DomainRegistrar(),
                DomainCreationDate(),
                DomainExpirationDate(),
                DomainAge(),
                DomainCountry(),
                DomainDNSSEC(),
                DomainOrganization(),
                DomainAddress(),
                DomainCity(),
                DomainState(),
                DomainZipcode(),
                DomainNameServers(),
                DomainUpdatedDate(),
                CharacterEntropy(),
                ContinuousNumericMaxLen(),
                ContinuousAlphabetMaxLen(),
                ContinuousConsonantsMaxLen(),
                ContinuousSameAlphabetMaxLen(),
                VowelsConsonantRatio(),
                ConvFreqVowelsConsonants(),
                DistinctTTLValues(),
                TTLValuesMin(),
                TTLValuesMax(),
                TTLValuesMean(),
                TTLValuesMode(),
                TTLValuesVariance(),
                TTLValuesStandardDeviation(),
                TTLValuesMedian(),
                TTLValuesSkewness(),
                TTLValuesCoefficientOfVariation(),
                DistinctARecords(),
                DistinctNSRecords(),
                AvgAuthorityResourceRecords(),
                AvgAdditionalResourceRecords(),
                AvgAnswerResourceRecords(),
                QueryResourceRecordType(),
                AnsResourceRecordType(),
                QueryResourceRecordClass(),
                AnsResourceRecordClass(),
            ]
        self.__features = self.__features + self.__dns_features
        self.__dns_feature_names = {feature.name for feature in self.__dns_features}

    def execute(self, data: list, data_lock, flows: list, features_ignore_list: list = [],
            label: str = "") -> list:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            extracted_data = []
            total_flows = len(flows)
            progress_interval = max(500, total_flows // 20) if total_flows else 500
            for flow_index, flow in enumerate(flows, start=1):
                features_of_flow = {}
                features_of_flow["flow_id"] = str(flow)
                features_of_flow["timestamp"] = datetime.fromtimestamp(flow.get_timestamp())
                features_of_flow["src_ip"] = flow.get_src_ip()
                features_of_flow["src_port"] = flow.get_src_port()
                features_of_flow["dst_ip"] = flow.get_dst_ip()
                features_of_flow["dst_port"] = flow.get_dst_port()
                features_of_flow["protocol"] = flow.get_protocol()
                is_dns_flow = flow.get_protocol() == "DNS"
                error_counts = {}
                for feature in self.__features:
                    if feature.name in features_ignore_list:
                        continue
                    if feature.name in self.__dns_feature_names and not is_dns_flow:
                        features_of_flow[feature.name] = None
                        continue
                    feature.set_floating_point_unit(self.floating_point_unit)
                    try:
                        features_of_flow[feature.name] = feature.extract(flow)
                    except Exception:
                        error_counts[feature.name] = error_counts.get(feature.name, 0) + 1
                        features_of_flow[feature.name] = None
                if error_counts:
                    summary = ", ".join(
                        f"{name} ({count})" for name, count in sorted(error_counts.items())
                    )
                    print(
                        f">> Feature extraction errors for flow {flow}: {summary}",
                        flush=True,
                    )
                features_of_flow["label"] = label
                extracted_data.append(features_of_flow)
                if total_flows and (
                    flow_index % progress_interval == 0 or flow_index == total_flows
                ):
                    print(
                        f">> Feature extraction progress: {flow_index}/{total_flows} flows",
                        flush=True,
                    )
            with data_lock:
                data.extend(extracted_data)
                del extracted_data