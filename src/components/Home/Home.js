import React, {Component} from 'react';
import PostPreviews from '../PostPreviews/PostPreviews';


class Home extends Component {
    constructor(props) {
        super(props);
    }

    render() {
        return <PostPreviews/>;
    }
}

Home.propTypes = {};

export default Home;