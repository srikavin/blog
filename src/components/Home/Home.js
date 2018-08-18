import React, {Component} from 'react';
import PostPreviews from '../PostPreviews/PostPreviews';
import DocumentTitle from 'react-document-title'

class Home extends Component {
    render() {

        return (
            <div>
                <DocumentTitle title='Blog'/>
                <PostPreviews/>
            </div>
        );
    }
}

Home.propTypes = {};

export default Home;