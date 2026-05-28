import os
import shutil
import pandas as pd
from datetime import datetime


def pkt_csv(eth,extra, llc,stp,arp,loop,dtp,isl,cdp,dhcp,flow_pred,FINAL_FILE_PATH, FINAL_FILE_NAME):
    if not os.path.exists(FINAL_FILE_PATH):
        os.makedirs(FINAL_FILE_PATH)
    else:
        for entry in os.listdir(FINAL_FILE_PATH):
            path = os.path.join(FINAL_FILE_PATH, entry)
            if os.path.isfile(path) or os.path.islink(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)

    pkt_df_eth = pd.DataFrame(eth)
    pkt_df_extra=pd.DataFrame(extra)

    pkt_df_eth.to_csv(f'{FINAL_FILE_PATH}/pkts_eth_{FINAL_FILE_NAME}',index=False)

    protos = []
    if len(llc) >0:
        protos.append(llc)
    if len(stp) >0:
        protos.append(stp)
    if len(loop) >0:
        protos.append( loop)
    if len(dtp) >0:
        protos.append(dtp)
    if len(isl) >0:
        protos.append(isl)
    if len(cdp) >0:
        protos.append(cdp)
    if len(dhcp) >0:
        protos.append(dhcp)
    if len(arp)>0:
        protos.append(arp)

    proto_data = True
    if len(protos)==1:
        df_inner_protocols = pd.DataFrame(protos[0])
    elif len(protos)==2:
        df_inner_protocols = pd.merge(pd.DataFrame(protos[0]), pd.DataFrame(protos[1]), on='pkt_num' ,how='outer')
    elif len(protos)>2:
        df_inner_protocols = pd.merge(pd.DataFrame(protos[0]), pd.DataFrame(protos[1]),  on='pkt_num' ,how='outer')
        for i in range(2,len(protos)):
            df_inner_protocols = pd.merge(df_inner_protocols, pd.DataFrame(protos[i]),  on='pkt_num' ,how='outer')
    else:
        proto_data = False

    if proto_data:
        df_inner_protocols.to_csv(f'{FINAL_FILE_PATH}/pkts_protocols_{FINAL_FILE_NAME}',index=False)

    df_inner = pd.merge(pkt_df_eth, pkt_df_extra, on='pkt_num', how='inner')
    df_inner = pd.merge(df_inner, pd.DataFrame(flow_pred), on='pkt_num',how='outer')
    if proto_data:
        df_inner = pd.merge(df_inner, df_inner_protocols, on='pkt_num' ,how='outer')

    df_inner.to_csv(f'{FINAL_FILE_PATH}/pkts_all_{FINAL_FILE_NAME}', index=False)

    print(f'packets csv Created at {FINAL_FILE_PATH} and protocols data is {proto_data}')

def flow_csv(list_dict, FINAL_FILE_PATH, FINAL_FILE_NAME, flow_output_path=None):
    dfs_list = []
    for dic in list_dict:
        dfs_list.append(pd.DataFrame([dic]))
    if len(dfs_list) > 2:
        final = pd.concat([dfs_list[0], dfs_list[1]])
        for df in dfs_list[2:]:
            final = pd.concat([final, df])
    elif len(dfs_list) == 2:
        final = pd.concat([dfs_list[0], dfs_list[1]])
    else:
        final = dfs_list[0].copy()

    final = final.drop_duplicates(keep='last')
    if flow_output_path:
        flow_output_path = os.path.abspath(flow_output_path)
        out_dir = os.path.dirname(flow_output_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        final.to_csv(flow_output_path, index=False)
        print(f'flows csv Created at {flow_output_path}')
        return

    timestamped = (
        f'{FINAL_FILE_PATH}/{datetime.now().strftime("%Y-%m-%d")}-'
        f'{datetime.now().time().strftime("%H-%M")}-final_flow-{FINAL_FILE_NAME}'
    )
    final.to_csv(timestamped, index=False)
    print(f'flows csv Created at {timestamped}')