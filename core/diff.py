from typing import Dict ,Any ,List 
class DiffEngine :
    def compare (self ,current :Dict [str ,Any ],previous :Dict [str ,Any ])->Dict [str ,Any ]:
        diff ={
        "rls":self ._diff_list (current .get ("findings",{}).get ("rls",[]),
        previous .get ("findings",{}).get ("rls",[]),
        key ="table"),
        "auth":self ._diff_auth (current .get ("findings",{}).get ("auth",{}),
        previous .get ("findings",{}).get ("auth",{})),
        "storage":self ._diff_list (current .get ("findings",{}).get ("storage",[]),
        previous .get ("findings",{}).get ("storage",[]),
        key ="bucket"),
        "rpc":self ._diff_list (current .get ("findings",{}).get ("rpc",[]),
        previous .get ("findings",{}).get ("rpc",[]),
        key ="name"),
        }
        return diff 
    def _diff_list (self ,curr :List [Dict ],prev :List [Dict ],key :str )->Dict [str ,List ]:
        curr_map ={item [key ]:item for item in curr }
        prev_map ={item [key ]:item for item in prev }
        new_items =[]
        resolved_items =[]
        unchanged_items =[]
        for k ,item in curr_map .items ():
            if k not in prev_map :
                new_items .append (item )
            else :
                unchanged_items .append (item )
        for k ,item in prev_map .items ():
            if k not in curr_map :
                resolved_items .append (item )
        return {"new":new_items ,"resolved":resolved_items ,"unchanged":unchanged_items }
    def _diff_auth (self ,curr :Dict ,prev :Dict )->Dict [str ,Any ]:
        curr_leaked =curr .get ("leaked",False )
        prev_leaked =prev .get ("leaked",False )
        status ="unchanged"
        if curr_leaked and not prev_leaked :status ="new_leak"
        elif not curr_leaked and prev_leaked :status ="resolved"
        return {"status":status ,"current_count":curr .get ("count",0 ),"previous_count":prev .get ("count",0 )}