import Head from "next/head";
import React, { useEffect, useState } from "react";
import Avatar from "../components/avatar";
import ChatList from "../components/rooms";
import Conversation from "../components/conversation";
import Login from "../components/login";
import useConversations from "../libs/useConversation";
import useLocalStorage from "../libs/useLocalStorage";
import useWebsocket from "../libs/useWebsocket";

export default function Home() {
  const [room, setSelectedRoom] = useState(null);
  const [isTyping, setIsTyping] = useState(false);
  const [showLogIn, setShowLogIn] = useState(false);
  const [auth, setAuthUser] = useLocalStorage("user", false);
  const [isLoading, messages, setMessages, fetchConversations] =
    useConversations("");

  const handleTyping = (mode) => {
    if (mode === "IN") {
      setIsTyping(true);
    } else {
      setIsTyping(false);
    }
  };

  const handleMessage = (msg, userId) => {
    setMessages((prev) => {
      const item = { content: msg, user_id: userId };
      return [...prev, item];
    });
  };

  const onMessage = (data) => {
    try {
      let messageData = JSON.parse(data);
      switch (messageData.chat_type) {
        case "TYPING": {
          handleTyping(messageData.value[0]);
          return;
        }
        case "TEXT": {
          handleMessage(messageData.value[0], messageData.user_id);
          return;
        }
      }
    } catch (e) {
      console.log(e);
    }
  };

  const sendMessage = useWebsocket(onMessage);
  const updateFocus = () => {
    const data = {
      id: 0,
      chat_type: "TYPING",
      value: ["IN"],
      room_id: room.id,
      user_id: auth.id,
    };
    sendMessage(JSON.stringify(data));
  };

  const onFocusChange = () => {
    const data = {
      id: 0,
      chat_type: "TYPING",
      value: ["OUT"],
      room_id: room.id,
      user_id: auth.id,
    };
    sendMessage(JSON.stringify(data));
  };

  const submitMessage = async (e) => {
    e.preventDefault();
    let message = e.target.message.value;
    if (message === "") {
      return;
    }

    if (!room.id) {
      alert("Please select chat room!");
      return;
    }

    const data = {
      id: 0,
      chat_type: "TEXT",
      value: [message],
      room_id: room.id,
      user_id: auth.id,
    };
    sendMessage(JSON.stringify(data));
    console.log(data);

    // Enviar mensagem para o backend
    try {
      const response = await fetch("http://localhost:8080/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          user_id: auth.id,
          room_id: room.id,
          content: message,
        }),
      });

      if (!response.ok) {
        throw new Error("Erro ao salvar mensagem");
      }

      const result = await response.json();
      console.log("Mensagem salva:", result);
    } catch (error) {
      console.error("Erro ao salvar mensagem:", error);
    }

    e.target.message.value = "";
    handleMessage(message, auth.id);
    onFocusChange();
  };

  const updateMessages = (data) => {
    if (!data.id) return;
    fetchConversations(data.id);
    setSelectedRoom(data);
  };

  const signOut = () => {
    window.localStorage.removeItem("user");
    setAuthUser(false);
  };

  useEffect(() => setShowLogIn(!auth), [auth]);

  return (
    <>
      <Head>
        <title>Mensagens Criptografadas</title>
        <meta name="description" content="Rust with react chat app" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      <Login show={showLogIn} setAuth={setAuthUser} />
      <div
        className={`${
          !auth && "hidden"
        } bg-gradient-to-t from-slate-800 to-indigo-600 h-screen p-12`}
      >
        <main className="flex w-full max-w-[1020px] h-[600px] mx-auto bg-[#FAF9FE] rounded-lg backdrop-opacity-30 opacity-95">
          <aside className="bg-[#F0EEF5] w-[325px] h-[600px] rounded-l-[25px] p-4 overflow-auto relative">
            <ChatList onChatChange={updateMessages} userId={auth.id} />
            <button
              onClick={signOut}
              className="text-xs w-full max-w-[295px] p-3 rounded-[10px] bg-gray-200 font-semibold text-black text-center absolute bottom-4"
            >
              SAIR
            </button>
          </aside>
          {room?.id && (
            <section className="rounded-r-[25px] w-full max-w-[690px] grid grid-rows-[80px_minmax(450px,_1fr)_65px]">
              <div className="rounded-tr-[25px] w-ful">
                <div className="flex gap-3 p-3 items-center">
                  <Avatar color="rgb(245 158 11)">
                    {room.users.get_target_user(auth.id)}
                  </Avatar>
                  <div>
                    <p className="font-semibold text-gray-600 text-base">
                      {room.users.get_target_user(auth.id)}
                    </p>
                    <div className="text-xs text-gray-400">
                      {isTyping ? "Digitando..." : "10:15 AM"}
                    </div>
                  </div>
                </div>
                <hr className="bg-[#F0EEF5]" />
              </div>
              {isLoading && room.id && (
                <p className="px-4 text-slate-500">Carregando conversas...</p>
              )}
              <Conversation data={messages} auth={auth} users={room.users} />
              <div className="w-full">
                <form
                  onSubmit={submitMessage}
                  className="flex gap-2 items-center rounded-lg border border-black bg-gray-200 p-1 m-2"
                >
                  <input
                    onBlur={onFocusChange}
                    onFocus={updateFocus}
                    autoComplete={"off"}
                    name="message"
                    className="p-2 placeholder-gray-600 text-sm w-full rounded-full bg-gray-200 focus:outline-none"
                    placeholder="Digite sua mensagem"
                  />
                  <button
                    type="submit"
                    className="bg-gray-500 rounded-lg py-2 px-6 font-semibold text-white text-sm"
                  >
                    Enviar
                  </button>
                </form>
              </div>
            </section>
          )}
        </main>
      </div>
    </>
  );
}
