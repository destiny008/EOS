### 多签系统/延迟交易中存在漏洞，可以使账号的所有权在交易后仍被控制
#### 1. 起因
tp群中有成员反映，自己购买的一个账户，在变更私钥后仍旧被重置成之前的私钥造成账号被控制，账号中的财产被盗取。

#### 2. 跟进
我们通过社群成员的账号相关的交易中看出，该账号在卖出/购入前，曾经参与过某个多签提案的审核。根据这个现象我们在本地测试环境中模拟了以下场景进行进一步的分析。

```
1.账户A提出一个多签的提案，需要账户A和账户B共同签署，内容是将账户B的私钥更新成BBB(举例)
2.账户A通过了这个提案
3.账户B通过了这个提案
4.账户B被出售给购买人，购买人提出并更换账户B的私钥为CCC
5.购买人为账户B充值并使用
6.账户A执行第一步的多签提案
7.账户B的私钥被重置为BBB（由于提案的内容刚被执行）
8.账户B被恶意控制，损失财产

```
通过上述的一个分析，我们发现在多签系统中，提案执行的时候并不会检查执行提案是的各个提案人的公钥信息，也就意味着提案执行时没有检查各个提案人的在执行的时候权限是否有过变更。
在`eosio.msig`代码中可以确认，执行多签提案的`exec()`函数中，在权限检查时没有将执行时的所有执行人的key传入到权限检查器当中去，而是使用了0来代替。这就能够说明提案在执行时没有校验各个执行人的权限信息是否仍旧满足当前的权限验证。

```c++
   auto res =  check_transaction_authorization(
                  prop.packed_transaction.data(), prop.packed_transaction.size(),
                  (const char*)0, 0,
                  packed_provided_approvals.data(), packed_provided_approvals.size()
               );

   check( res > 0, "transaction authorization failed" );

   send_deferred( (uint128_t(proposer.value) << 64) | proposal_name.value, executer,
                  prop.packed_transaction.data(), prop.packed_transaction.size() );
```

#### 3. 同步
在确认了这个问题后，我们第一时间跟block.one进行了同步，而block.one其实很早就已经知道此问题，是2018年19月份在githab上提交的，

https://github.com/EOSIO/eosio.contracts/issues/53

在githab的问题页面有提出有方法可以避免该问题发生，就是在账户交易完成后立即调用`multisig::invalidate()`这个方法，可以将此账户移除处已经审核通过但是尚未被执行的多签提案中，从而避免上述问题。从代码可以看出，调用`multisig::invalidate()`后会将账户和当前时间添加到`inv_table`表中。
```c++
void multisig::invalidate( name account ) {
   require_auth( account );
   invalidations inv_table( get_self(), get_self().value );
   auto it = inv_table.find( account.value );
   if ( it == inv_table.end() ) {
      inv_table.emplace( account, [&](auto& i) {
            i.account = account;
            i.last_invalidation_time = current_time_point();
         });
   } else {
      inv_table.modify( it, account, [&](auto& i) {
            i.last_invalidation_time = current_time_point();
         });
   }
}
```
一旦`multisig::exec()`执行的时候，会在`inv_table`中确认审核人的账户是否存在于`inv_table`表中，或者审核人审核的时间是否大于调用`invalidate()`的时间。一旦审核人信息不存在表中或者审核人调用`invalidate()`的时间早于审核的时间，则都会认同此次审核人的权限成立而使此次提案被成功执行。
```c++
   if ( apps_it != apptable.end() ) {
      approvals.reserve( apps_it->provided_approvals.size() );
      for ( auto& p : apps_it->provided_approvals ) {
         auto it = inv_table.find( p.level.actor.value );
         if ( it == inv_table.end() || it->last_invalidation_time < p.time ) {
            approvals.push_back(p.level);
         }
      }
      apptable.erase(apps_it);
   } else {
```

#### 4. 扩展
同样的，由于多签系统是基于延迟交易从而存在的问题，那么延迟交易经过验证同样也存在相同的问题。经过测试，使用延迟交易也能够将改过私钥的账户在延迟执行时更换。由于延迟交易受限于3888000秒的最大延迟时间，也就是45天，所以延迟交易也有一个等待45天以上的简单方法用于规避账户交易风险。


#### 5. 结论
在目前环境下账户买卖在EOS中仍旧存在很多问题，还是建议用户尽量自己创建账户进行交易。如果参与了账户交易，务必要先查看所购买账户的操作列表是否存在权限的敏感操作，例如updateauth/approve，优先第一时间执行`multisig::invalidate()`操作来取消多签提案所带来的影响，并且建议不要成为主要的钱包地址使用。
