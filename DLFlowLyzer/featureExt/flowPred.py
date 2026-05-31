import numpy as np
import pandas as pd
from . import flowFeatureExt
from time import sleep


def flow_flag_res_fin_split(df, fin_indexes, res_indexes):
    if len(fin_indexes)<1 and len(res_indexes)<1:
        return [df]
    fin_indexes+=res_indexes
    fin_indexes.insert(0,-1)
    flows = []
    if len(fin_indexes)>0:
        for i in range(1,len(fin_indexes)):
            if fin_indexes[i] == df.index[-1]:
                continue
            tmp = df.loc[fin_indexes[i-1]+1:fin_indexes[i]]
            if len(tmp)<3:
                try:
                    flows[-1]=pd.concat([flows[-1], tmp], axis=0).sort_values('pkt_num')
                except:
                    flows.append(tmp)
            else:
                flows.append(tmp)
            # flows.append(tmp)
    else:
        flows.append(df)
    return flows
def flow_pred(file, EXTRA, FEATURES, CAP_UDP):
    df = pd.read_csv(file)
    bbb = []

    if CAP_UDP:
        aaa = df.query("connection=='UDP'").groupby(df[['dist_addr', 'src_addr','src_ip', 'dst_ip', 'src_port', 'dst_port']].apply(frozenset, axis=1))
        bbb += [aaa.get_group(x) for x in aaa.groups]
        del (aaa)


    ddd = df.query("connection=='TCP'").groupby(df[['tcp_stream', 'dist_addr', 'src_addr','src_ip', 'dst_ip', 'src_port', 'dst_port']].apply(frozenset, axis=1))
    bbb += [ddd.get_group(x) for x in ddd.groups]
    del (ddd)

    if EXTRA:
        ccc = df.query("connection!='TCP' or connection!='UDP'").groupby(df[['dist_addr', 'src_addr']].apply(frozenset, axis=1))
        bbb += [ccc.get_group(x) for x in ccc.groups]
        del (ccc)


    dfs = []
    checked = []
    for i in range(len(bbb)):
        in_it = -1
        if bbb[i].iloc[0]['connection'] == 'TCP':
            if len(checked) > 0:
                _, stream = zip(*checked)
                if bbb[i].iloc[0]['tcp_stream'] not in stream:
                    checked.append([i, bbb[i].iloc[0]['tcp_stream']])
                else:
                    in_it = stream.index(bbb[i].iloc[0]['tcp_stream'])
            else:
                checked.append([i, bbb[i].iloc[0]['tcp_stream']])

            tmp = flow_flag_res_fin_split(bbb[i], bbb[i]['tcp_fin_ack'].loc[lambda x: x == 1].index.tolist(),
                                          bbb[i]['tcp_res'].loc[lambda x: x == 1].index.tolist())
            if in_it > -1:
                for z in range(len(tmp)):
                    dfs[in_it] = pd.concat([dfs[in_it], tmp[z]])
            else:
                dfs += tmp
        else:
            dfs.append(bbb[i])

    del (bbb)
    del (checked)

    csv_dict = []
    for grp in dfs:
        grouped_df = grp.copy()
        csv_dict.append(flowFeatureExt.flow_feature_ext(grouped_df, EXTRA, FEATURES))

    return csv_dict