#include <stdio.h>
#include <jansson.h>

void print_addr(void *addr)
{
	printf("Addr: %p\n", addr);
}

void print_string(char *string)
{
	printf("Unsecure Print: %s\n", string);
}

char *serialize_user(All_Users all_users[])
{
	json_t *results = json_array();

	for (size_t i = 0; i < all_users->size; i++)
	{
		json_t *user = json_object();
		json_object_set_new(user, "username", json_string(all_users->users[i].username));
		json_object_set_new(user, "account_number", json_integer(all_users->users[i].account_number));

		json_array_append_new(results, user);
	}

	return json_dumps(results, 0);
}

char *serialize_balance(All_Balances all_balances[])
{
	json_t *results = json_array();

	for (size_t i = 0; i < all_balances->size; i++)
	{
		json_t *balance = json_object();
		json_object_set_new(balance, "amount", json_real(all_balances->balances[i].balance));
		json_object_set_new(balance, "account_number", json_integer(all_balances->balances[i].account_number));

		json_array_append_new(results, balance);
	}

	return json_dumps(results, 0);
}
Account_U user_string_to_account(char *user_string)
{
	printf("Ocall_User_String: %s\n", user_string);
	json_t *user_obj = json_loads(user_string, 0, NULL);

	Account_U user;

	user.username = (char *)json_string_value(json_object_get(user_obj, "username"));
	user.account_number = json_integer_value(json_object_get(user_obj, "account_number"));

	return user;
}

Account_B balance_string_to_account(char *balance_string)
{
	printf("Ocall_Balance_String: %s\n", balance_string);
	json_t *user_obj = json_loads(balance_string, 0, NULL);

	Account_B balance;

	balance.balance = json_real_value(json_object_get(user_obj, "amount"));
	balance.account_number = json_integer_value(json_object_get(user_obj, "account_number"));

	return balance;
}

Balance_Entry string_to_balance_entry(char *string)
{
	json_t *balance_entry = json_loads(string, 0, NULL);

	Balance_Entry b_entry;

	b_entry.type = (char *)json_string_value(json_object_get(balance_entry, "type"));
	b_entry.account_number = json_integer_value(json_object_get(balance_entry, "account_number"));
	b_entry.amount = json_real_value(json_object_get(balance_entry, "amount"));

	return b_entry;
}