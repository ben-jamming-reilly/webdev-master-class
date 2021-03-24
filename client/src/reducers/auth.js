const initialState = {
  tmp: "tmp"
};

function authReducer(state = initialState, action) {
  const { type, payload } = action;

  switch (type) {
    case "TMP":
      return state;
    default:
      return state;
  }
}

export default authReducer;